from . import ConfigParserCrypt as configparser
from xrpl.models.transactions import PaymentChannelClaim, PaymentChannelClaimFlag
from xrpl.constants import CryptoAlgorithm
from xrpl.transaction import submit_and_wait
from xrpl.wallet import Wallet
import logging
import os
import time
import traceback
from xrpl.clients import JsonRpcClient
from xrpl.account import get_balance
from xrpl.models.requests import Tx
from xrpl.models import Payment
from xrpl.core import keypairs
from xrpl.core.binarycodec.main import encode_for_signing_claim
import threading

# Logging cleaned up

# Let's get the configuration file and read it
config = configparser.ConfigParserCrypt()
config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config.ini'))
parser = config.config_read(config_path)  # Read the configuration file


class LedgerTools:

    def __init__(self):
        self.logger = logging.getLogger(f"xdrip.{__name__}")
        self.logger.debug("Init LedgerTools")
        self.JSON_RPC_URL = parser.get('Ledger', 'ledger_url')
        self.client = JsonRpcClient(self.JSON_RPC_URL)
        choice = parser.get('Wallet', 'algorithm')
        self.algo = self.setAlgorithm(choice)
        self._lock = threading.Lock()


    def setAlgorithm(self, choice):
        """
            Set the algorithm for the wallet seed derivation
        """
        try:
            algos = {
                "secp256k1": CryptoAlgorithm.SECP256K1,
                "ed25519": CryptoAlgorithm.ED25519,
            }
            if choice is None:
                raise Exception("Missing algorithm choice for wallet")
            
            if choice not in algos.keys():
                raise Exception("Invalid algorithm choice for wallet")
            
            return algos[choice]

        except Exception as e:
            self.logger.error(f"Error in setAlgorithm, failed to set algorithm: {e}")
            raise e


    def convert_epoch(self, epoch):
        """
            Convert the XRPL epoch to a standard epoch
            Given a XRPL epoch, return a standard unix epoch
            XRP -> Unix
        """
        try:
            return int(epoch) + 946684800
        
        except Exception as e:
            self.logger.error(f"Error in convert_epoch, failed to convert epoch: {e}")
            raise e
    

    def ledger_time_as_epoch(self):
        """
            Get the current ledger time as standard epoch
            Given current time, return the ledger epoch value
            Unix -> XRP
        """
        try:
            return int(time.time()) - 946684800
        
        except Exception as e:
            self.logger.error(f"Error in ledger_time_as_epoch, failed to get ledger time as epoch: {e}")
            raise e


    def get_tx_details(self, tx_hash):
        # Create a Transaction request and have the client call it
        try:
            tx_request = Tx(transaction=tx_hash)
            tx_response = self.client.request(tx_request)

            return tx_response
        
        except Exception as e:
            self.logger.error(f"Error in  get_tx_details, failed to get transaction details: {e}")
            raise e
    

    def parse_refresh_tx(self, response, update_epoch=True):
        """
        Parse the refresh transaction, extract fields and return a dictionary
        :param response: The response from the ledger
        :return: A dictionary with the transaction details
        """
        obj = {}
        result = response.result
        try:
            # Get the transaction details
            obj['validation'] = result['meta']['TransactionResult']
            obj['account'] = result['Account']
            obj['amount'] = result['Amount']
            obj['channel_id'] = result['Channel']
            obj['expiration'] = result['Expiration']
            obj['fee'] = result['Fee']
            obj['flags'] = result['Flags']
            obj['last_ledger_sequence'] = result['LastLedgerSequence']
            obj['sequence'] = result['Sequence']
            obj['signing_pubkey'] = result['SigningPubKey']
            obj['transaction_type'] = result['TransactionType']
            obj['txn_signature'] = result['TxnSignature']
            obj['ctid'] = result['ctid']
            if update_epoch:
                obj['date'] = self.convert_epoch(result['date'])
            else:
                obj['date'] = result['date']
            obj['hash'] = result['hash']
            obj['in_ledger'] = result['inLedger']
            obj['ledger_index'] = result['ledger_index']

            xrp_meta_fields = [
                "DeletedNode",
                "ModifiedNode",
                "CreatedNode",
                "PreviousFields",
                "FinalFields",
                "NewFields"
            ]

            for node in result['meta']['AffectedNodes']:
                for meta_field in xrp_meta_fields:
                    if meta_field in node and node[meta_field].get('LedgerEntryType') == 'PayChannel':
                        obj['ledger_entry_type'] = node[meta_field]['LedgerEntryType']
                        final_fields = node[meta_field]['FinalFields']

                        # Extracting relevant fields from FinalFields
                        obj['final_state_meta'] = meta_field
                        obj['final_account'] = final_fields.get('Account', None)
                        obj['final_amount'] = final_fields.get('Amount', None)
                        obj['final_balance'] = final_fields.get('Balance', None)
                        obj['final_cancel_after'] = final_fields.get('CancelAfter', None)
                        obj['final_destination'] = final_fields.get('Destination', None)
                        obj['final_destination_node'] = final_fields.get('DestinationNode', None)
                        obj['final_destination_tag'] = final_fields.get('DestinationTag', None)
                        obj['final_expiration'] = final_fields.get('Expiration', None)
                        obj['final_flags'] = final_fields.get('Flags', None)
                        obj['final_owner_node'] = final_fields.get('OwnerNode', None)
                        obj['final_public_key'] = final_fields.get('PublicKey', None)
                        obj['final_settle_delay'] = final_fields.get('SettleDelay', None)

                        break  # exit the loop once the desired data is found

            return obj

        except Exception as e:
            self.logger.error(f"Error in parse_refresh_tx, failed to parse refresh transaction: {e}")
            raise e



    def parse_channel_tx(self, response, update_epoch=True):
        """
        Parse the channel transaction
        :param response: The response from the ledger
        :return: A dictionary with the transaction details
        """
        obj = {}
        result = response.result

        try:
            # Get the transaction details
            obj['validation'] = result['meta']['TransactionResult']
            obj['account'] = result['Account']
            obj['destination'] = result['Destination']
            obj['amount'] = result['Amount']
            obj['publickey'] = result['PublicKey']
            obj['settle_delay'] = result['SettleDelay']
            obj['transaction_type'] = result['TransactionType']
            obj['ctid'] = result['ctid']
            if 'DestinationTag' in result:
                obj['destination_tag'] = int(result['DestinationTag'])
            # Convert the epoch to a standard epoch
            if update_epoch:
                obj['date'] = self.convert_epoch(result['date'])
            else:
                obj['date'] = result['date']
            obj['hash_id'] = result['hash']
            obj['ledger_index'] = result['ledger_index']
            # - Note, this should cause error, as CancelAfter is not accepted by this system
            if 'CancelAfter' in result:
                obj['cancel_after'] = self.convert_epoch(result['CancelAfter'])
            channel_id = None
            
            # Get the channel id
            for node in result['meta']['AffectedNodes']:
                if 'CreatedNode' in node and node['CreatedNode']['LedgerEntryType'] == 'PayChannel':
                    channel_id = node['CreatedNode']['LedgerIndex']
                    break
            obj['channel_id'] = channel_id  

            # Get the memo details (first memo only), set None if no memo
            memo = None
            if 'Memos' in result:
                try:
                    memo = bytes.fromhex(result['Memos'][0]['Memo']['MemoData']).decode('utf-8')
                except Exception as e:
                    self.logger.warning(f"Failed to decode memo: {e} from TX: {result['hash']}")

            obj['memo'] = memo   
            
            return obj
        
        except Exception as e:
            self.logger.error(f"Error in parse_channel_tx, failed to parse channel transaction: {e}")
            raise e


    def verify_signature(self, signature=None, channel_id=None, amount=None, public_key=None):
        """
            Verify the signature
        """
        if signature is None or channel_id is None or amount is None or public_key is None:
            self.logger.error("Error in verify_signature, missing required parameters")
            raise Exception("Error in verify_signature, missing required parameters")
        
        # Response from the ledger
        verified = False

        if type(amount) is str:
            amount = int(amount)
        
        try:
            # Create the verify request
            json = {"amount": amount, "channel": channel_id}
            encoded = encode_for_signing_claim(json)
            verified = keypairs.is_valid_message(bytes.fromhex(encoded), bytes.fromhex(signature), public_key)
        
        except Exception as e:
            self.logger.error(f"Error in verify_signature, failed to verify signature: {e}")
            verified = False

        return verified


    def make_channel_claim(self, channel_id=None, amount=None, signature=None, public_key=None):
        """
            Make a channel claim
        """
        if channel_id is None or amount is None or signature is None or public_key is None:
            self.logger.error("Error in make_channel_claim, missing required parameters")
            raise Exception("Error in make_channel_claim, missing required parameters")
        
        claim_response = None
        error = None

        try:
            # Convert amount to string if int
            if isinstance(amount, int):
                amount = str(amount)

            with self._lock:
                drip_wallet_secret = parser.get('Wallet', 'secret_encrypted')
                drip_wallet = Wallet.from_seed(drip_wallet_secret, algorithm=self.algo)

                claim_tx = PaymentChannelClaim(
                    account=drip_wallet.classic_address,
                    channel=channel_id,
                    balance=amount,
                    signature=signature,
                    public_key=public_key,
                    flags=PaymentChannelClaimFlag.TF_CLOSE,
                )
                claim_response = submit_and_wait(claim_tx, self.client, drip_wallet)
                claim_response = claim_response.result

                self.logger.info(f"Channel claim for Amount: {amount} for channel: {channel_id}. Response for {drip_wallet.classic_address}: {claim_response}")

        except Exception as e:
            self.logger.error(f"Error in make_channel_claim, failed to make channel claim: {e}")
            error = f"Error: TX Failed {e}"
        
        return claim_response, error


    def _offload_to_coldwallet(self):
        """
            Offload the funds to a cold wallet when server hot wallet is over the threshold
        """
        try:
            drip_wallet_secret = parser.get('Wallet', 'secret_encrypted')
            drip_wallet = Wallet.from_seed(drip_wallet_secret, algorithm=self.algo)

            offload_wallet_address = parser.get('Wallet', 'offload_classic_address')
            threadhold = parser.getint('Wallet', 'offload_over_threshold', fallback=20000000)
            drip_wallet_balance = get_balance(drip_wallet.address, self.client)
            if drip_wallet_balance >= threadhold:
                transfer_amount = (drip_wallet_balance - threadhold)
                self.logger.info(f"Server wallet over threasold, offloading {transfer_amount} to cold wallet {offload_wallet_address}")

                # Create a Payment transaction
                with self._lock:
                    string_transfer_amount = str(transfer_amount)
                    payment_tx = Payment(
                        account=drip_wallet.address,
                        amount=string_transfer_amount,
                        destination=offload_wallet_address,
                        # What goes here, validate just in case
                    )

                    # Signs, autofills, and submits transaction and waits for response
                    payment_response = submit_and_wait(payment_tx, self.client, drip_wallet)
                    payment_response = payment_response.result
                    self.logger.info(f"Offload transaction response: {payment_response}")

                # Save transaction to the filesystem as a log
                # - Ensure we can write out the claim information to a file
                # - Check if the 'coldtx' directory exists and create it if not
                coldtx_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'coldtx'))
                if not os.path.exists(coldtx_dir):
                    self.logger.info(f"Creating coldtx directory, as it did not exist: {coldtx_dir}")
                    os.makedirs(coldtx_dir)

                # Create the file and write out the claim information
                filename = f"{int(time.time())}_coldtx.log"
                claims_path = os.path.join(coldtx_dir, filename)  

                with open(claims_path, 'w') as fx:
                    fx.write(str(payment_response))
        
        except Exception:
            tbe = traceback.format_exc()
            self.logger.error(f"Error in _offload_to_coldwallet, failed to offload to cold wallet: {tbe}")
            # Swallow the exception, we don't want to stop the server