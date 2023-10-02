#!/usr/bin/env python3
from xrpl.clients import JsonRpcClient
from xrpl.constants import CryptoAlgorithm
from xrpl.models.transactions import PaymentChannelCreate, PaymentChannelFund, Memo
from xrpl.core.binarycodec.main import encode_for_signing_claim
from xrpl.transaction import submit_and_wait
from xrpl.core import keypairs
from xrpl.wallet import Wallet
import traceback
import grpc
import grpc_drip_server_pb2 as drip_pb2
import grpc_drip_server_pb2_grpc as drip_grpc
import uuid
import jwt
import random
import sys
import time

# Define some ANSI escape codes for colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Constants
GRPC_SERVER_ADDRESS = "localhost:50051"
GRPC_SERVER_CERT_PATH = "server_cert.pem"
JWT_ALGORITHMS = ["ES256"]
RANDOM_QUIT_MIN = 3600
RANDOM_QUIT_MAX = 28800
RANDOM_PAYMENT_AMOUNT_MIN = 0
RANDOM_PAYMENT_AMOUNT_MAX = 99
RANDOM_SLEEP_MIN = 1
RANDOM_SLEEP_MAX = 30
TTL_PRE_REFRESH = 300
MAX_RETRIES = 3
RPC_NETWORK = "https://s.altnet.rippletest.net:51234"
WEB_SESSION_ID = str(uuid.uuid4())
WALLET_ALGO = CryptoAlgorithm.ED25519

## Add as many as you want/need for testing
# seq 25 | parallel -j25 --delay 5 'python test_client.py >> client_output.txt'
SEED_FARM = ["sEdSTxxxxxxxxxxxxxxxxxxxxxxxxxx", "sEdSuxxxxxxxxxxxxxxxxxxxxxxxxxx", "sEdTPxxxxxxxxxxxxxxxxxxxxxxxxxx", 
             "sEd7hxxxxxxxxxxxxxxxxxxxxxxxxxx", "sEd7sxxxxxxxxxxxxxxxxxxxxxxxxxx", "sEdTKxxxxxxxxxxxxxxxxxxxxxxxxxx", 
             "sEd7dxxxxxxxxxxxxxxxxxxxxxxxxxx", "sEdTgxxxxxxxxxxxxxxxxxxxxxxxxxx", "sEdTDxxxxxxxxxxxxxxxxxxxxxxxxxx",
             "sEdTaxxxxxxxxxxxxxxxxxxxxxxxxxx", "sEd76xxxxxxxxxxxxxxxxxxxxxxxxxx", "sEdTQxxxxxxxxxxxxxxxxxxxxxxxxxx",
             "sEd7Qxxxxxxxxxxxxxxxxxxxxxxxxxx", "sEdTgxxxxxxxxxxxxxxxxxxxxxxxxxx", "sEdSAxxxxxxxxxxxxxxxxxxxxxxxxxx",
             "sEd75xxxxxxxxxxxxxxxxxxxxxxxxxx", "sEdTUxxxxxxxxxxxxxxxxxxxxxxxxxx", "sEdVYxxxxxxxxxxxxxxxxxxxxxxxxxx",
             "sEdSoxxxxxxxxxxxxxxxxxxxxxxxxxx", "sEdTdxxxxxxxxxxxxxxxxxxxxxxxxxx", "sEd75xxxxxxxxxxxxxxxxxxxxxxxxxx",
             "sEdTFxxxxxxxxxxxxxxxxxxxxxxxxxx", "sEd7Uxxxxxxxxxxxxxxxxxxxxxxxxxx", "sEdTzxxxxxxxxxxxxxxxxxxxxxxxxxx", 
             "sEdTdxxxxxxxxxxxxxxxxxxxxxxxxxx"] # 25 seeds / Clients


WALLET_SEED = random.choice(SEED_FARM)
print(f"Random Wallet Seed Chosen: {WALLET_SEED}\n")


def convert_epoch(epoch: int) -> int:
    """
    Convert the XRPL epoch to a standard epoch.
    
    Args:
        epoch: XRPL epoch timestamp.
    
    Returns:
        int: A standard Unix epoch timestamp.
    """
    return int(epoch) + 946684800


def ledger_time_as_epoch() -> int:
    """
    Get the current ledger time as a standard epoch.
    
    Returns:
        int: The ledger epoch value.
    """
    return int(time.time()) - 946684800


def get_channel_details(response) -> tuple:
    """
    Extracts the channel details from the given response.
    
    Args:
        response: Response from the transaction.
    
    Returns:
        tuple: Channel details and transaction hash.
    """
    txhash = response.result.get('hash', '')
    for node in response.result.get('meta', {}).get('AffectedNodes', []):
        created_node = node.get('CreatedNode', {})
        if created_node.get('LedgerEntryType') == 'PayChannel':
            details = {'ChannelID': created_node.get('LedgerIndex')}
            details.update(created_node.get('NewFields', {}))
            return details, txhash
    return None, None  # Return None if not found


def create_payment_channel(client, client_wallet, proposal_id=None, destination_address=None, 
                           amount=None, settle_delay=None, public_key=None, destination_tag=None) -> tuple:
    """
    Creates a payment channel.
    
    Args:
        client: XRPL client instance.
        client_wallet: Wallet object for the client.
        proposal_id: The ID for the proposal.
        destination_address: Destination address for the payment.
        amount: Amount to be transferred.
        settle_delay: Settling delay for the payment.
        public_key: Client's public key.
        cancel_after: Time after which the transaction will be cancelled.
        destination_tag: Destination tag for the transaction.
    
    Returns:
        tuple: Channel details and transaction hash.
    """
    try:
        proposal_id = proposal_id.encode("utf-8").hex()
        memo = Memo(memo_data=proposal_id)

        payment_channel_create_tx = PaymentChannelCreate(
            account=client_wallet.classic_address,
            amount=str(amount), 
            destination=destination_address,
            settle_delay=settle_delay,
            public_key=public_key,
            destination_tag=destination_tag,
            memos=[memo]
        )
        response = submit_and_wait(payment_channel_create_tx, client, client_wallet)
        return get_channel_details(response)
    except Exception as e:
        raise ValueError(f"Error creating payment channel: {e}")


def fund_payment_channel(client, client_wallet, channel_id=None, amount=None, expiration=None) -> tuple:
    """
    Fund an existing payment channel.
    
    Args:
        client: XRPL client instance.
        client_wallet: Wallet object for the client.
        channel_id: ID of the channel to be funded.
        amount: Amount to fund.
        expiration: Expiration time of the fund.
    
    Returns:
        tuple: Response from the transaction and transaction hash.
    """
    try:
        payment_channel_fund_tx = PaymentChannelFund(
            account=client_wallet.classic_address,
            channel=channel_id,
            amount=str(amount),
            expiration=expiration,
        )
        response = submit_and_wait(payment_channel_fund_tx, client, client_wallet)
        txhash = response.result.get('hash', '')
        return response, txhash
    except Exception as e:
        raise ValueError(f"Error funding payment channel: {e}")


def hex_to_string(hex_value: str) -> str:
    """
    Convert a hexadecimal value to a string.
    
    Args:
        hex_value: The hexadecimal value.
    
    Returns:
        str: Converted string.
    """
    try:
        return bytes.fromhex(hex_value).decode('utf-8')
    except ValueError:
        raise ValueError("Invalid hex value")


def sign_claim(channel_id: str, amount_drops: int, wallet) -> str:
    """
    Sign a claim using the client's wallet.
    
    Args:
        channel_id: ID of the channel.
        amount_drops: Amount in drops to be claimed.
        wallet: Wallet object for the client.
    
    Returns:
        str: Signature for the claim.
    """
    try:
        json_to_sign = {"amount": str(amount_drops), "channel": channel_id}
        encoded = encode_for_signing_claim(json_to_sign)
        return keypairs.sign(bytes.fromhex(encoded), wallet.private_key)
    except Exception as e:
        raise ValueError(f"Error signing claim: {e}")


def decode_jwt_payload(JWTP, jwt_public_key, algorithms=JWT_ALGORITHMS):
    """
    Decodes the given JWT payload using the provided public key and algorithms.

    Parameters:
    - JWTP (str): The JWT payload to decode.
    - jwt_public_key (str): The public key to use for decoding.
    - algorithms (list): A list of algorithms to use for decoding.

    Returns:
    - payload (dict): The decoded payload if successful.
    - None if there's an error.
    """
    eject = True
    try:
        payload = jwt.decode(JWTP, jwt_public_key, algorithms=algorithms)
        eject = False
    except jwt.ExpiredSignatureError:
        error = "ERR: Token has expired"
        print(f"Error verifying inquiry payload: {error}")
    except jwt.InvalidTokenError:
        error = "ERR: Invalid token"
        print(f"Error verifying inquiry payload: {error}")
    except Exception as e:
        error = f"ERR: {e}"
        print(f"Error verifying inquiry payload: {e}")
    if eject:
        print("Error verifying inquiry payload, exiting")
        return None
    return payload


def create_drip_engine_stub(server_cert_path=GRPC_SERVER_CERT_PATH, server_address=GRPC_SERVER_ADDRESS):
    """
    Create and return a stub for the DripEngineService using gRPC secure channel.

    Parameters:
    - server_cert_path (str): Path to the server certificate.
    - server_address (str): Address of the gRPC server.

    Returns:
    - stub (object): An instance of DripEngineServiceStub for the gRPC server.
    """
    try:    
        with open(server_cert_path, "rb") as f:
            trusted_certs = f.read()

        credentials = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
        channel = grpc.secure_channel(server_address, credentials)
        stub = drip_grpc.DripEngineServiceStub(channel)

        return stub

    except Exception as e:
        tbe = traceback.format_exc()
        print(f"Error creating gRPC stub: {e}\n{tbe}\n")
        sys.exit()


def generate_random_values():
    """
    Generates random values for the payment amount and sleep time.

    Returns:
    - random_amount (int): The random payment amount.
    - random_sleep (int): The random sleep time.
    """
    random_amount = random.randint(RANDOM_PAYMENT_AMOUNT_MIN, RANDOM_PAYMENT_AMOUNT_MAX)
    random_sleep = random.randint(RANDOM_SLEEP_MIN, RANDOM_SLEEP_MAX)
    return random_amount, random_sleep


def create_session(stub, web_session_id):
    """
    Create a session using the provided stub and web session ID.
    
    Args:
        stub: The gRPC stub used for making calls.
        web_session_id: The ID of the web session.
        
    Returns:
        The response received after creating the session.
    """
    create_session_request = drip_pb2.CreateSessionRequest(session_id=web_session_id)
    create_session_response = stub.CreateSession(create_session_request)
    print(f"Received response for CreateSession:\n{create_session_response}\n")
    
    return create_session_response


def get_session(stub, web_session_id, drip_token):
    """
    Gets a session using the provided session id and drip token.

    Parameters:
    - stub: The gRPC stub for communication.
    - web_session_id: The session id associated with the session.
    - drip_token: The token associated with the session.

    Returns:
    - The response from the server for the GetSession request.
    """
    get_session_request = drip_pb2.GetSessionRequest(session_id=web_session_id, drip_token=drip_token)
    get_session_response = stub.GetSession(get_session_request)
    print(f"{GREEN}Received response for GetSession:{RESET}\n{get_session_response}\n")
    return get_session_response


def client_inquiry(stub, drip_token):
    """
    Perform a ClientInquiry using the provided stub and drip token.
    
    Args:
        stub: The gRPC stub used for making calls.
        drip_token: The token associated with the drip session.
        
    Returns:
        The response received after performing the ClientInquiry.
    """
    client_inquiry_request = drip_pb2.ClientInquiryRequest(drip_token=drip_token)
    client_inquiry_response = stub.ClientInquiry(client_inquiry_request)
    print(f"Received response for ClientInquiry:\n{client_inquiry_response}\n")
    
    return client_inquiry_response


def get_owed_info(stub, drip_token, web_session_id):
    """
    Gets the amount owed using the provided drip token.

    Parameters:
    - stub: The gRPC stub for communication.
    - drip_token: The token associated with the session.

    Returns:
    - The response from the server for the GetOwedInfo request.
    """
    get_owed_info_request = drip_pb2.GetOwedInfoRequest(drip_token=drip_token, session_id=web_session_id)
    get_owed_info_response = stub.GetOwedInfo(get_owed_info_request)
    print(f"{CYAN}Received response for GetOwedInfo:{RESET}\n{get_owed_info_response}\n")
    return get_owed_info_response


def process_payment(stub, get_owed_info_response, drip_token, channel_id, client_wallet):
    """
    Processes a payment using the provided drip token.

    Parameters:
    - stub: The gRPC stub for communication.
    - get_owed_info_response: The response from the server for the GetOwedInfo request.
    - drip_token: The token associated with the session.
    - channel_id: The ID of the channel to be used for payment.
    - client_wallet: Wallet object for the client.

    Returns:
    - The response from the server for the ProcessPayment request.
    """
    if get_owed_info_response.AmountDue > get_owed_info_response.AmountPaid:
        print(f"{RED}Amount owed: {get_owed_info_response.AmountDue}{RESET}")
        amount_due = int(get_owed_info_response.AmountDue)
        # Make a payment 
        signature = sign_claim(channel_id, amount_drops=amount_due, wallet=client_wallet)

        print(f"Wallet Address {client_wallet.classic_address}\nAmount: {amount_due}\nChannel ID: {channel_id}\nSignature: {signature}\n\n")

        make_payment_request = drip_pb2.ProcessPaymentRequest(drip_token=drip_token, amount=amount_due, signature=signature)
        make_payment_response = stub.ProcessPayment(make_payment_request)
        print(f"{MAGENTA}Signature: {signature}{RESET}")
        print(f"{BLUE}Received response for MakePayment:{RESET}\n{make_payment_response}\n")

        return make_payment_response
    
    else:
        print(f"{GREEN}Amount owed: {get_owed_info_response.AmountDue} less then or eq Amount paid: {get_owed_info_response.AmountPaid}{RESET}")
        return None


def make_debt_claim(stub, drip_token, random_amount, payment_state):
    """
    Makes a debt claim using the provided drip token.

    Parameters:
    - stub: The gRPC stub for communication.
    - drip_token: The token associated with the session.
    - random_amount: The random amount to be claimed.
    - payment_state: The current payment state.

    Returns:
    - The response from the server for the MakeUnitPayment request.
    """
    print(f"{YELLOW}Making debt claim for {random_amount} units....{RESET}")
    if payment_state not in ['paid', 'pending']:
        print(f"Skipping debt query, as we are not in paid or pending state. STATE: {payment_state}")
        return None
    else:    
        make_payment_request = drip_pb2.MakeUnitPaymentRequest(drip_token=drip_token, amount=random_amount)
        make_payment_response = stub.MakeUnitPayment(make_payment_request)
        print(f"{CYAN}Received response for MakeUnitPayment:{RESET}\n{make_payment_response}\n")
        return make_payment_response


def refresh_inquiry_and_accept(stub, drip_token, jwt_public_key, client, client_wallet, channel_id):
    """
    Refreshes an inquiry and accepts the refresh.

    Parameters:
    - stub: The gRPC stub for communication.
    - drip_token: The token associated with the session.
    - jwt_public_key: The public key to use for decoding.
    - client: XRPL client instance.
    - client_wallet: Wallet object for the client.
    - channel_id: ID of the channel to be funded.

    Returns:
    - The response from the server for the ClientRefreshInquiry request.
    - The amount of the refresh.

    """
    try:
        refresh_inquiry_request = drip_pb2.ClientRefreshInquiryRequest(drip_token=drip_token)
        refresh_inquiry_response = stub.ClientRefreshInquiry(refresh_inquiry_request)
        print(f"{GREEN}Received response for ClientRefreshInquiry:{RESET}\n{refresh_inquiry_response}\n")

        # Refresh the payment channel
        JWTR = refresh_inquiry_response.JWT
        payload = decode_jwt_payload(JWTR, jwt_public_key)

        # Extract the fields from the payload
        drip_token = payload["DripToken"]
        amount = int(payload["MinChannelFunding"])
        expiration = payload["SettlementDate"]

        response, txhash = fund_payment_channel(client, client_wallet, channel_id=channel_id, amount=amount, expiration=expiration)
        
        # Craft payload to accept the refresh
        client_refresh_accept_request = drip_pb2.ClientRefreshAcceptRequest(Action="RefreshAgreement", TXHash=txhash, JWTPayload=JWTR)
        client_refresh_accept_response = stub.ClientRefreshAccept(client_refresh_accept_request)
        print(f"{BLUE}Received response for ClientRefreshAccept:{RESET}\n{client_refresh_accept_response}\n")

        return client_refresh_accept_response, amount
    
    except Exception as e:
        print(f"Error refreshing channel: {e}")
        return None, None


def destroy_session(stub, drip_token):
    """
    Destroys a session using the provided drip token.

    Parameters:
    - stub: The gRPC stub for communication.
    - drip_token: The token associated with the session.

    Returns:
    - The response from the server for the DestroySession request.
    """
    destroy_session_request = drip_pb2.DestroySessionRequest(drip_token=drip_token)
    destroy_session_response = stub.DestroySession(destroy_session_request)
    print(f"Received response for DestroySession:\n{destroy_session_response}\n")
    return destroy_session_response


def send_accept_agreement_request(stub, txhash, JWTP):
    """
    Sends a client accept agreement request to the server and prints the response.

    Parameters:
    - stub: The gRPC stub for communication.
    - txhash: The transaction hash associated with the request.
    - JWTP: The token for the JWT payload.

    Returns:
    - The response received from the server for the ClientAcceptAgreement request.
    """
    
    client_accept_agreement_request = drip_pb2.ClientAcceptAgreementRequest(Action="Agreement", TXHash=txhash, JWTPayload=JWTP)
    client_accept_agreement_response = stub.ClientAcceptAgreement(client_accept_agreement_request)
    print(f"Received response for ClientAcceptAgreement:\n{client_accept_agreement_response}\n")
    
    return client_accept_agreement_response


def run():
    """
    The main function for the client.

    Description:
    - Creates a session.
    - Gets the session.
    - Performs a client inquiry.
    - Accepts the agreement.
    - Makes a few payments via Unit Based Payments, a mock client session.
    - Attempts to refreshes the channel if needed.
    - Destroys the session.

    Returns:
    - None
    """
    stub = create_drip_engine_stub()

    print(f"Starting client execution {stub}\n")

    session_exists = True

    try:
        ## CreateSession
        # Make a call to CreateSession
        web_session_id = WEB_SESSION_ID

        create_session_response = create_session(stub, web_session_id)
        drip_token = create_session_response.DripToken
        uri = create_session_response.URI
        jwt_public_key = uri.split("/")[-1]
        print(f"Drip token: {drip_token}\nURI: {uri}\nJWT Public Key: {jwt_public_key}\n\n")
        jwt_public_key = hex_to_string(jwt_public_key)

        ## GetSession
        get_session(stub, web_session_id, drip_token)

        ## Setup Wallet and Connection
        client = JsonRpcClient(RPC_NETWORK)
        # Clients Wallet
        client_wallet = Wallet.from_seed(WALLET_SEED, algorithm=WALLET_ALGO)

        ## ClientInquiry
        client_inquiry_response = client_inquiry(stub, drip_token)

        ## Accept the Agreement, create the payment channel
        JWTP = client_inquiry_response.JWT
        payload = decode_jwt_payload(JWTP, jwt_public_key)

        # Extract the fields from the payload
        proposal_id = payload["ProposalID"]
        destination_address = payload["DestinationAddress"]
        amount = payload["MinChannelFunding"]
        settle_delay = payload["SettlementDelay"]
        public_key = client_wallet.public_key
        destination_tag = payload["DestinationTag"]
        # Other useful fields
        drip_token = payload["DripToken"]

        # Create the payment channel
        # - CancleAfter is not supported due to the nature of how the XRPL handles updates, CancleAfter is immutable once set. 
        results, txhash = create_payment_channel(client, 
                                                client_wallet, 
                                                proposal_id=proposal_id, 
                                                destination_address=destination_address,
                                                amount=amount, 
                                                settle_delay=settle_delay, 
                                                public_key=public_key, 
                                                destination_tag=destination_tag)
        
        # Extract the channel ID from the results
        channel_id = results["ChannelID"]

        # Craft the payload for the client accept agreement request
        send_accept_agreement_request(stub, txhash, JWTP)

        ## Make a few payments via Unit Based Payments, a mock client session
        current_epoch = int(time.time())
        random_quit = random.randint(RANDOM_QUIT_MIN, RANDOM_QUIT_MAX) + current_epoch

        while True:
            random_amount, random_sleep = generate_random_values()
            
            print(f"Current Epoch: {int(time.time())}")
            
            session_response = get_session(stub, web_session_id, drip_token)
            if session_response.Message == "Err: Session not found":
                print(f"{RED}Session not found, exiting.{RESET}")
                session_exists = False
                break

            owed_info_response = get_owed_info(stub, drip_token, web_session_id)
            process_payment(stub, owed_info_response, drip_token, channel_id, client_wallet)

            # Do we need to refresh the channel?
            # - Expire window default of 180, claim at 120 seconds
            if (owed_info_response.TTL - TTL_PRE_REFRESH) <= int(time.time()):
                time_left = owed_info_response.TTL - int(time.time())
                print(f"{YELLOW}Refreshing the channel, {time_left} seconds left before expires.{RESET}")
                resp, resp_amount = refresh_inquiry_and_accept(stub, drip_token, jwt_public_key, client, client_wallet, channel_id)
                if not resp:
                    print(f"{RED}Error refreshing channel, nearing end of channel life, skipping.{RESET}")


            elif owed_info_response.State in ["nsf", "expired"]:
                print(f"{RED}Invalid channel balance, attempting to refresh channel.{RESET}")
                resp, resp_amount = refresh_inquiry_and_accept(stub, drip_token, jwt_public_key, client, client_wallet, channel_id)
                if not resp:
                    print(f"{RED}Error refreshing channel, bad payment state, skipping.{RESET}")

            
            # Attempt to make a debt claim against the channel for this session
            if random_amount > 0:
                claim_response = make_debt_claim(stub, drip_token, random_amount, session_response.PaymentState)
                if claim_response:
                    if claim_response.Message == "ERR: Debt exceeds channel balance":
                        print(f"{RED}Debt exceeds channel balance, attempting to refresh channel.{RESET}")
                        resp, resp_amount = refresh_inquiry_and_accept(stub, drip_token, jwt_public_key, client, client_wallet, channel_id)
                        if not resp:
                            print(f"{RED}Error refreshing channel, failed debt claim, skipping.{RESET}")


            # Quit after a random number of iterations
            if int(time.time()) >= random_quit:
                print(f"{RED}Quitting after {random_quit} iterations.{RESET}")
                break

            else:
                print(f"Client quitting in {random_quit - int(time.time())} seconds")
            
            time.sleep(random_sleep)


    finally:
        print(f"End of client execution\n")
        if session_exists:
            ## DestroySession
            destroy_session_response = destroy_session(stub, drip_token)
            print(f"Received response for DestroySession:\n{destroy_session_response}\n")

if __name__ == '__main__':
    run()
