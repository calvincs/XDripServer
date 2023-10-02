from mods.ConfigParserCrypt import ConfigParserCrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from mods.GenSecrets import generate_es256_keys, generate_self_signed_cert
from mods.ValidateConfig import validate_ini
import mods.DripEngine as drip
import mods.DripEngineServicer as des
import os
import sys
import time
import logging
from logging.handlers import RotatingFileHandler
from concurrent import futures
import threading
import signal
import grpc
import grpc_drip_server_pb2_grpc as drip_grpc
import traceback

## Logging cleaned

## - Helper Functions, Thread Funcitons & Main
if "DRIP_SECRET" not in os.environ:
    print("Please set the DRIP_SECRET environment variable, see README.md for more information.")
    sys.exit(1)

# Global exit event
exit_event = threading.Event()


def create_signal_handler(server):
    def signal_handler(signum, frame):
        exit_event.set()
        server.stop(0)
    return signal_handler


def claim_and_clean_tasks(drip_coffee, interval):
    while not exit_event.is_set():
        drip_coffee._claim_and_clean()
        exit_event.wait(interval)


def increment_payment_state_tasks(drip_coffee, interval):
    while not exit_event.is_set():
        drip_coffee._increment_time_based_rates()
        drip_coffee._past_due_kicker()
        exit_event.wait(interval)


def update_payment_state_tasks(drip_coffee, interval):
    while not exit_event.is_set():
        drip_coffee._update_ledger_state()
        exit_event.wait(interval)


def offload_hot_wallet(drip_coffee, interval):
    while not exit_event.is_set():
        drip_coffee._offload_to_coldwallet()
        exit_event.wait(interval)     


def manage_lock_file(condition, logger):
    """
    Manages the lock file based on the provided condition and logs the results.
    
    Parameters:
    - condition (str): "startup" to create/check the lock file, "shutdown" to remove the lock file.
    - logger (logging.Logger): Instance of the logger to use for logging.
    
    Returns:
    - bool: True if the operation was successful, otherwise False.
    """
    
    lock_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "xdrip_server.lock"))
    
    try:
        if condition == "startup":
            # Check if lock file exists
            if os.path.exists(lock_file_path):
                with open(lock_file_path, "r") as f:
                    existing_pid = f.read().strip()
                logger.error(f"StartUp Error - The lock file already exists with PID: {existing_pid}, kill the process and remove the lock file to start the server.")
                return False
            
            # If not, create the lock file with the current PID
            else:
                pid = os.getpid()
                with open(lock_file_path, "w") as f:
                    f.write(str(pid))
                logger.info("StartUp - Lock file created successfully.")
                return True

        elif condition == "shutdown":
            # Remove the lock file if it exists
            if os.path.exists(lock_file_path):
                os.remove(lock_file_path)
                logger.info("Shutdown - Lock file removed successfully.")
                return True
            
            else:
                logger.warning("Shutdown - Lock file does not exist.")
                return False
        
        else:
            raise Exception("invalid condition specified.")
    
    except Exception as e:
        logger.error(f"An error occurred in manage_lock_file: {str(e)}")
        return False


def main():
    try:
        # - Report the configuration file validation results
        config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'config.ini'))
        is_valid_config, config_message = validate_ini(config_path)
        if not is_valid_config:
            print(f"Configuration file validation failed: {config_message}, exiting...")
            sys.exit(1)

        ## Let's get the configuration file and read it
        config = ConfigParserCrypt()
        parser = config.config_read(config_path)

        ## Setup the logger
        logger = logging.getLogger("xdrip")

        #Get the log level from the config file
        log_level = parser.get('System', 'log_level', fallback='INFO').upper()
        if log_level == 'INFO':
            log_level = logging.INFO
        elif log_level == 'DEBUG':
            log_level = logging.DEBUG
        elif log_level == 'WARNING':
            log_level = logging.WARNING
        elif log_level == 'ERROR':
            log_level = logging.ERROR
        elif log_level == 'CRITICAL':
            log_level = logging.CRITICAL
        else:
            log_level = logging.INFO

        logger.setLevel(log_level)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(module)s.%(funcName)s] %(message)s')
        
        # Get absolute path to the log file
        log_file = os.path.abspath(os.path.join(os.path.dirname(__file__), 'logs/xdrip-server.log'))
        if not os.path.exists(os.path.dirname(log_file)):
            os.makedirs(os.path.dirname(log_file))

        # - File Handler
        max_bytes = parser.getint('System', 'log_file_size_mb', fallback=100) * 1024 * 1024
        log_file_count = parser.getint('System', 'log_file_count', fallback=10)    
        file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=log_file_count)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # - Console Handler
        if parser.getboolean('System', 'log_to_console', fallback=False):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        # Lets ensure we have a lock file, we are the only instance of the server running
        if not manage_lock_file("startup", logger):
            sys.exit(1)

        ## Lets ensure we have PKI keys for JWTs
        jwt_response = parser.get('System', 'jwt_private_encrypted', fallback=False)
        if not jwt_response:
            logger.warning("No JWT keys found, generating new ES256 keys for system.")
            # Generate the keys
            key_pair = generate_es256_keys()
            # Save the keys to the configuration file
            parser.set('System', 'jwt_private_encrypted', key_pair[0].decode('utf-8'))
            parser.set('System', 'jwt_public_encrypted', key_pair[1].decode('utf-8'))
            # Write the configuration file
            config.config_write(config_path)


        ## Init the Drip Engine
        drip_coffee = drip.DripEngine()


        ## Threads
        # - Start Claim and Clean Thread, which will execute every 30 seconds
        logger.info("Starting the Claim and Clean thread, will execute approximatly every 30 seconds.")
        claim_task_thread = threading.Thread(target=claim_and_clean_tasks, args=(drip_coffee, 30))

        # - Start Payment State Thread, which will execute every 5 seconds
        logger.info("Starting the Update Payment State thread, will execute approximatly every 5 seconds.")
        update_task_thread = threading.Thread(target=update_payment_state_tasks, args=(drip_coffee, 5))

        # - Start Increment Payment State Thread, which will execute every polling interval
        polling_interval = parser.getint('Terms', 'payment_polling_interval', fallback=60)
        logger.info(f"Starting the Increment Payment State thread, will execute approximatly every {polling_interval} seconds.")
        increment_task_thread = threading.Thread(target=increment_payment_state_tasks, args=(drip_coffee, polling_interval))

        # - Start Offload Hot Wallet Thread, which will executes based on the offload interval
        offload_interval = parser.getint('SchedulesAndSettings', 'offload_interval_seconds', fallback=300)
        logger.info(f"Starting the Offload Hot Wallet thread, will execute every {offload_interval} seconds.")
        offload_task_thread = threading.Thread(target=offload_hot_wallet, args=(drip_coffee, offload_interval))

        ## Start the gRPC server
        # - Fetch the passphrase from the environment
        passphrase = os.environ["DRIP_SECRET"].encode('utf-8')
        # - Do we need to generate a self-signed certificate?
        if not (os.path.exists("cert.pem") and os.path.exists("key.pem")):
            if parser.getboolean('gRPC_Certificate', 'generate_self_signed_cert', fallback=False):
                logger.warning("No certificates found, generating new self-signed certificate.")
                generate_self_signed_cert()
            else:
                logger.error("No certificate found, and generate_self_signed_cert is set to False. Please see README.md for more information.")
                sys.exit(1)

        # - Load the certificate and key
        server_cert_pem_name = parser.get('gRPC_Certificate', 'server_cert_name')
        server_cert_pem_path = os.path.abspath(os.path.join(os.path.dirname(__file__), server_cert_pem_name))
        with open(server_cert_pem_path, "rb") as f:
            cert = f.read()

        server_cert_key_name = parser.get('gRPC_Certificate', 'server_key_name')   
        server_cert_key_path = os.path.abspath(os.path.join(os.path.dirname(__file__), server_cert_key_name))
        with open(server_cert_key_path, "rb") as f:
            key = serialization.load_pem_private_key(
                f.read(),
                password=passphrase,
                backend=default_backend()
            )

        server_credentials = grpc.ssl_server_credentials([(key.private_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.PKCS8, 
            encryption_algorithm=serialization.NoEncryption()), 
            cert)])

        # - Set the worker pool size and start the server
        max_grpc_workers = parser.getint('System', 'max_grpc_workers', fallback=10)
        grpc_port = parser.getint('System', 'grpc_port', fallback=50051)
        logger.info(f"Starting the gRPC server on port {grpc_port}, with a maximum of {max_grpc_workers} workers.")
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_grpc_workers))
        drip_grpc.add_DripEngineServiceServicer_to_server(des.DripEngineServicer(drip_coffee), server)
        server.add_secure_port(f"[::]:{grpc_port}", server_credentials)
        
        # Lets start our threads, including the server threads
        claim_task_thread.start()
        update_task_thread.start()
        increment_task_thread.start()
        offload_task_thread.start()
        server.start()

        # Register the signal handler with access to the server variable
        signal.signal(signal.SIGINT, create_signal_handler(server))
        signal.signal(signal.SIGTERM, create_signal_handler(server))
        signal.signal(signal.SIGTSTP, create_signal_handler(server))

        # Wait for the exit event to be set
        while not exit_event.is_set():
            time.sleep(1)
        else:
            logger.info("Exit event set to server, attempting claim and offload before shutdown.")
            drip_coffee._claim_and_clean(flush=True)
            drip_coffee._offload_to_coldwallet()
            logger.info("Waiting for threads to complete before shutting down.")
            server.stop(0)

        # Wait for the threads to finish
        claim_task_thread.join()
        update_task_thread.join()
        increment_task_thread.join()
        offload_task_thread.join()

        # Remove the lock file
        manage_lock_file("shutdown", logger)

    except Exception as e:
        tbe = traceback.format_exc()
        print(f"Fatal error encountered in main {e}: {tbe}")
        exit_event.set()
        sys.exit(1)

    logger.info("Server shutdown complete.")

if __name__ == '__main__':
    main()
