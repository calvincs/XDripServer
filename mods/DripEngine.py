# DripEngine Imports
from ulid import ULID
import json
import jwt
import datetime
from . import LedgerTools as ledger
from . import ConfigParserCrypt as configparser
from . import ModelFuncs as mdefs
import traceback
import logging
import os
import math
import time

## Cleaned Logging

class DripEngine:

    def __init__(self):
        self.logger = logging.getLogger("xdrip.engine")
        self.parser = self._get_parser()
        self._payload_secret = None
        self._payload_public = None
        self.lts = ledger.LedgerTools()

# - Exposed functions


    def CreateSession(self, session_id=None):
        """
        Creates a new session in the database and returns the session information
            :param session_id: The session ID from the web server
            :type session_id: str
            :return: A dictionary containing the session information
            :rtype: dict
        """
        resp_obj = {}
        try:
            self.logger.info(f"Creating new session for '{session_id}'")
            domain = self.parser.get('System', 'domain')
            drip_token = str(ULID())
            public_key = str(self.parser.get('System', 'jwt_public_encrypted')).encode().hex()

            deep_link = f"xdrip://{domain}/{drip_token}/{public_key}"

            # Send to the database
            mdefs.new_session(session_id=session_id,
                                        drip_token=drip_token, 
                                        domain=domain, 
                                        uri=deep_link)
            resp_obj = {
                "Action": "SessionCreated",
                "SessionID": session_id,
                "DripToken": drip_token,
                "Domain": domain,
                "URI": deep_link
            }

        except Exception as e:
            self.logger.error(f"Error in CreateSession from '{session_id}' creation: {e}")

            if "Session already exists" in str(e):
                error = "ERR: Session already exists"
            else:
                error = f"ERR: unknown error during session creation"
            resp_obj = {"Action": "CreateSession", "Message": error}
        
        return resp_obj


    def DestroySession(self, session_id=None, drip_token=None):
        """
        Destroys a session on Server
            Can be called by the web server or the client
        """
        resp_obj = {}
        try:
            self.logger.info(f"Destroying session:'{session_id}' drip_token:'{drip_token}'")

            # Use session_id to get the drip_token
            resp_db = mdefs.get_session(session_id=session_id, drip_token=drip_token)

            _rec_drip_token = resp_db.drip_token
            _rec_client_address = resp_db.client_address

            # Send to the database, if the client address is not None, we are destroying the session outright
            # - If there is an active payment associated to the session, just set to destroy it. 
            if _rec_client_address is None:
                resp_db = mdefs.delete_session_record(drip_token=_rec_drip_token)
            else:
                resp_db = mdefs.set_to_destroy(drip_token=_rec_drip_token)

            # Check if the session exists
            self.logger.info(f"Destroy session response from server:'{resp_db}'")
            if resp_db is None:
                resp_obj = {
                    "Action": "DestroySession",
                    "Message": "Session not found"
                }
            else:
                resp_obj = {
                    "Action": "DestroySession",
                    "Message": "Session destroyed"
                }

        except Exception as e:
            self.logger.error(f"Error destroying session '{session_id}':{e}")
            resp_db = {"Action" : "DestroySession", "Message": "ERR: unknown error during session creation"}
        
        return resp_obj


    def GetSession(self, session_id=None, drip_token=None):
        """
        Queries the database for an existing session and returns the session information
            :param session_id: The session ID from the web server
            :type session_id: str
            :param drip_token: The drip token from the web server
            :type drip_token: str
            :return: A dictionary containing the session information
            :rtype: dict
        """
        resp_obj = {}
        try:
            self.logger.info(f"GetSession query for '{session_id}' drip_token:'{drip_token}'")

            # Send to the database
            resp_db = mdefs.get_session(session_id, drip_token)

            # Check if the session exists
            if resp_db is None:
                resp_obj = {
                    "Action": "QuerySession",
                    "Message": "Err: Session not found"
                }
            else:
                resp_obj = {
                    "Action": "QuerySession",
                    "SessionID": resp_db.session_id,
                    "DripToken": resp_db.drip_token,
                    "Domain": resp_db.domain,
                    "URI": resp_db.uri,
                    "PaymentState": resp_db.payment_state,
                    "ClientAddress": resp_db.client_address,
                    "Message": "Session found"
                }

            self.logger.debug(f"GetSession query response returned: {resp_obj}")

        except Exception as e:
            self.logger.error(f"Error creating new session: {e}")
            resp_db = {"Action": "QuerySession", "Message": "ERR: unknown error during session query"}
        
        return resp_obj


    def ClientInquiry(self, drip_token=None):
        """
        Creates a client inquiry payload for the client to poll for payments
            :param drip_token: The drip token from the web server
            :type drip_token: str
            :return: A dictionary containing the inquiry information, as a JWT token
        """
        resp_obj = {}
        try:
            self.logger.info(f"ClientInquiry query for drip_token:'{drip_token}'")

            # First need to verify that the drip token and domain are valid
            is_session = mdefs.get_session(drip_token=drip_token)
            if is_session is None:
                raise Exception("Err: Invalid session or drip token")
            
            # Domain of the Drip Server
            domain = self.parser.get('System', 'domain')

            # Payment Type we are using
            payment_terms = ["Both", "TimeBased", "UnitBased"]
            payment_type = self.parser.getint('Terms', 'payment_type')
            
            # Get the Inquiry expiration time
            inquiry_expiration = self.parser.getint('Terms', 'inquiry_expiration')

            # Polling Interval to check for payments required
            polling_interval = self.parser.getint('Terms', 'payment_polling_interval')

            # Minimum Channel Funding
            min_channel_funding = self.parser.getint('Terms', 'min_channel_funding')

            # When should we settle the channel by
            channel_expiration = self.parser.getint('Terms', 'channel_expiration')

            # Destination Address
            destination_address = self.parser.get('Wallet', 'classic_address')
            destination_tag = self.parser.getint('Terms', 'destination_tag', fallback=0)

            # Target Currency
            target_currency = self.parser.get('Terms', 'target_currency', fallback="XRP")
            
            # Return the inquiry payload
            tmp_data = {
                "Action": "Proposal",
                "DripToken": drip_token,
                "Domain": domain,
                "ProposalID": str(ULID()),
                "ProposalExpires": inquiry_expiration,
                "PaymentType": payment_terms[payment_type],
                "Rate": 0,
                "PollingInterval": polling_interval,
                "MinChannelFunding": min_channel_funding,
                "SettlementDelay": channel_expiration,
                "DestinationAddress": destination_address,
                "DestinationTag": destination_tag,
                "TargetCurrency": target_currency,
            }

            # If the payment type is Both or TimeBased, we need to calculate the rate
            if tmp_data["PaymentType"] in ["TimeBased", "Both"]:
                # If XRP/XRP+ this in drops, where 1 is the smallest allowed value, always
                polling_interval = tmp_data["PollingInterval"]
                segments = int(channel_expiration / polling_interval)
                calculated_rate = int(math.ceil(min_channel_funding / segments))
                if calculated_rate == 0:
                    calculated_rate = 1
                tmp_data["Rate"] = calculated_rate
                self.logger.info(f"ClientInquiry calculated rate: {calculated_rate} for inquiry proposal_id: {tmp_data['ProposalID']}")

            # Generate the JWT token
            dat, error = self._generate_jwt(tmp_data, ttl=inquiry_expiration)
            if error:
                raise Exception(error)
            resp_obj["Action"] = "Proposal"
            resp_obj["Message"] = "Proposal created successfully"
            resp_obj["JWT"] = dat

            self.logger.debug(f"ClientInquiry query response returned: {resp_obj}")

        except Exception as e:
            self.logger.error(f"Error creating inquiry payload: {e}")
            resp_obj = { "Action" : "InquiryError", "Message": "ERR: General System Error" }
        
        return resp_obj


    def ClientAcceptAgrement(self, payload=None):
        """
        Accepts the agreement from the client and creates the agreement in the database
            :param payload: The payload from the client
            :type payload: dict
            :return: A dictionary containing the agreement information, as a JWT token, and error message if applicable
        """ 
        resp_obj = {}
        try:
            #Ensure the payload contains all the valid fields required
            required_keys = ["Action", "TXHash", "JWTPayload"]
            for key in required_keys:
                if key not in payload:
                    self.logger.error(f"Error creating client agreement: '{key}' not in payload")
                    raise Exception("ERR: Invalid payload")
                
                if payload[key] is None or payload[key] == "":
                    self.logger.error(f"Error creating client agreement: '{key}' is None or empty")
                    raise Exception("ERR: Invalid payload")
                
            if payload["Action"] != "Agreement":
                self.logger.error(f"Error creating client agreement: '{payload['Action']}' is not 'Agreement'")
                raise Exception("ERR: Invalid payload")
            
            self.logger.info(f"ClientAcceptAgreement payload:'{payload}'")
                
            # Verify the Payload
            result, error = self._validate_agreement(payload=payload)
            if error:
                raise Exception("ERR: Invalid payload")

            # Create the agreement in the database
            resp_obj, error = self._accept_client_agreement(validated_object=result)
            if error:
                raise Exception(error)
            
            # Create ledger entry to track payment states
            mdefs.new_ledger_record(proposal_id=result['_proposal_id'], 
                                    drip_token=result['_drip_token'],
                                    channel_balance=result['_min_channel_funding'],
                                    rate=result['_rate'],
                                    payment_type=result['_payment_type'])

            # Set the payment state of the session to pending
            mdefs.update_payment_state(drip_token=result['_drip_token'], payment_state="pending")
            
        except Exception as e:
            tbh = traceback.format_exc()
            self.logger.error(f"ClientAcceptAgreement error in accepting client agreement: {tbh}")
            # On error
            if "ERR:" in str(e):
                error = str(e)
            else:
                error = "ERR: General System Error"
            resp_obj = { "Action" : "AgreementDenied", "Message": error}
        
        return resp_obj


    def ClientRefreshInquiry(self, drip_token=None):
        """
        Creates a client refresh inquiry payload for the client, effectivley extending the expiration time
            :param drip_token: The drip token from the web server
            :type drip_token: str
            :return: A dictionary containing the refresh inquiry information, as a JWT token
        """
        resp_obj = {}
        try:
            self.logger.info(f"ClientRefreshInquiry from drip_token:'{drip_token}'")

            # First need to verify that the drip token and domain are valid
            is_session = mdefs.get_session(drip_token=drip_token)
            if is_session is None:
                raise Exception("Err: Invalid drip token during session lookup")
            
            # Get previous agreement information from the agreements table
            agreement_info = mdefs.get_agreement(drip_token=drip_token)
            if agreement_info is None:
                raise Exception("Err: Invalid drip token during agreement lookup")
            
            
            # Get the Inquiry expiration time, calculate the new expiration time
            channel_expiration = self.parser.getint('Terms', 'channel_expiration')
            inquiry_expiration = self.parser.getint('Terms', 'inquiry_expiration')
            new_expiration = int(self.lts.ledger_time_as_epoch() + channel_expiration + inquiry_expiration)

            # Minimum Channel Funding
            min_channel_funding = int(agreement_info.min_channel_funding) + self.parser.getint('Terms', 'min_channel_funding')

            # Return the proposal id
            proposal_id = agreement_info.proposal_id

            # Channel ID
            channel_id = agreement_info.channel_id

            # Return the inquiry payload
            tmp_data = {
                "Action": "RefreshProposal",
                "DripToken": drip_token,
                "ProposalID": proposal_id,
                "ProposalExpires": inquiry_expiration,
                "MinChannelFunding": min_channel_funding,
                "SettlementDate": new_expiration,  # This is an XRPL Epoch value, client needs to covert as needed, if needed
                "ChannelID": channel_id,
            }

            # Generate the JWT token
            dat, error = self._generate_jwt(tmp_data, ttl=inquiry_expiration)
            if error:
                raise Exception(error)
            
            resp_obj["Action"] = "RefreshProposal"
            resp_obj["Message"] = "RefreshProposal created successfully"
            resp_obj["JWT"] = dat

            self.logger.debug(f"ClientRefreshInquiry response returned: {resp_obj}")

        except Exception:
            tbe = traceback.format_exc()
            self.logger.error(f"ClientRefreshInquiry error creating refresh inquiry: {tbe}")
            resp_obj = { "Action" : "RefreshProposalError", "Message": "ERR: General System Error"}
        
        return resp_obj


    def ClientRefreshAccept(self, payload=None):
        """
        Accepts the refresh agreement from the client and updates the agreement in the database
            :param payload: The payload from the client
            :type payload: dict
            :return: A dictionary containing the agreement information, as a JWT token, and error message if applicable
        """ 
        resp_obj = {}
        try:
            #Ensure the payload contains all the valid fields required
            required_keys = ["Action", "TXHash", "JWTPayload"]
            for key in required_keys:
                if key not in payload:
                    self.logger.error(f"Error refreshing client agreement: '{key}' not in payload")
                    raise Exception("ERR: Invalid payload")
                
                if payload[key] is None or payload[key] == "":
                    self.logger.error(f"Error refreshing client agreement: '{key}' is None or empty")
                    raise Exception("ERR: Invalid payload")
                
            if payload["Action"] != "RefreshAgreement":
                self.logger.error(f"Error refreshing client agreement: '{payload['Action']}' is not 'RefreshAgreement'")
                raise Exception("ERR: Invalid payload")
                
            self.logger.info(f"ClientRefreshAccept payload:'{payload}'")

            # Verify the Payload
            result, error = self._validate_refresh_agreement(payload=payload)
            if error:
                self.logger.error(f"Error validating client refresh agreement: {error}")
                raise Exception("ERR: Unable to validate payload or transaction")
            
            # Update ledger entry to track payment states
            count = mdefs.refresh_agreement(proposal_id=result['_proposal_id'], drip_token=result['_drip_token'], min_channel_funding=result['_min_channel_funding'], expires=result['_expires'])
            if count == 0:
                raise Exception("ERR: Failed to update agreement")
            
            self.logger.info(f"ClientRefreshAccept accepted for drip token: '{result['_drip_token']}'")
            
            return { "Action" : "RefreshApproved", "Message": "Refresh agreement accepted successfully"}

        except Exception as e:
            tbh = traceback.format_exc()
            self.logger.error(f"ClientRefreshAccept error accepting agreement: {tbh}, payload: {payload}")
            # On error
            if "ERR:" in str(e):
                error = str(e)
            else:
                error = "ERR: General System Error"
            resp_obj = { "Action" : "RefreshDenied", "Message": error}
        
        return resp_obj

        

    def MakeUnitPayment(self, session_id=None, drip_token=None, amount=None):
        """
            Make a unit payment
            :param session_id: The session ID from the web server
            :type session_id: str
            :param drip_token: The drip token from the web server
            :type drip_token: str
            :param amount: The amount to pay
            :type amount: int
            :return: A dictionary containing the payment information and error message if applicable
        """
        resp_obj = {}
        try:
            self.logger.info(f"MakeUnitPayment amount: '{amount}' for session_id: '{session_id}' or drip_token: '{drip_token}'")

            if session_id is None and drip_token is None:
                error = "ERR: Require session_id or drip_token"
                raise Exception(error)
            if amount is None:
                error = "ERR: Require amount value"
                raise Exception(error)
            
            # We need to get some information from the database
            response = mdefs.get_session(session_id=session_id, drip_token=drip_token)
            if not response:
                error = "ERR: Session not found"
                raise Exception(error)
            
            # Lets do some validate
            # - Is the session in a state that allows payments?
            if response.payment_state not in ["pending", "paid"]:
                error = "ERR: Session awaiting payment, unable allow debt"
                raise Exception(error)
            
            # - Is the session set to be removed?
            if response.destroyed:
                error = "ERR: Session is set to be removed"
                raise Exception(error)
            
            # Normalize, ensure we have both values
            session_id = response.session_id
            drip_token = response.drip_token

            # - Now lets validate against the ledger table
            state = mdefs.ledger_preapproval(drip_token=drip_token, amount=amount)
            # -- Does this session allow for unit based payments?
            if state[2] not in ["UnitBased", "Both"]:
                error = "ERR: Session is not configured for unit based debts"
                raise Exception(error)

            # -- Do we have enough balance in the channel to request the payment?
            if state[3] == "exceeds":
                error = "ERR: Debt exceeds channel balance"
                raise Exception(error)
            
            elif state[3] == "within_limit":
                self.logger.info(f"MakeUnitPayment debt within channel limit: '{state}' for '{drip_token}'")
            
            # If we made it this far, we are ok to add the payment to the ledger
            affected = mdefs.ledger_add_unitdebt(drip_token=drip_token, amount=amount)
            if affected == 0:
                error = "ERR: Failed to add debt to ledger"
                raise Exception(error)
            self.logger.info(f"MakeUnitPayment '{drip_token}' added debt amount '{amount}' to ledger")

            resp_obj = {
                "Action": "PurchaseApproved",
                "Message": "Purchase debt added to ledger successfully"
            }

        except Exception as e:
            self.logger.error(f"Error making unit payment: {e}, {drip_token}, {amount}")
            if "ERR:" in str(e):
                error = str(e)
            else:
                error = "ERR: General System Error"
            resp_obj = {"Action" : "PurchaseDenied", "Message": f"{error}"}

        return resp_obj
        

    def GetOwedInfo(self, drip_token=None, session_id=None):
        """
            Get the amount owed for a session
            :param drip_token: The drip token from the web server
            :type drip_token: str
            :param session_id: The session ID from the web server
            :type session_id: str
            :return: A dictionary containing the amount owed and error message if applicable, or error message if applicable
        """
        resp_obj = {}
        try:
            self.logger.info(f"GetOwedInfo for session_id: '{session_id}' or drip_token: '{drip_token}'")

            # Validate input
            if not drip_token and not session_id:
                raise Exception("Either drip_token or session_id must be provided.")

            results = mdefs.get_owed_amount(drip_token=drip_token, session_id=session_id)

            if not results:
                resp_obj = {
                    "Action": "AmountDue",
                    "Message": "Err: Session not found"
                }

            else:
                # Process and return the results
                resp_obj = {
                        "Action": "AmountDue",
                        'Domain': results[0],
                        'ProposalID': results[1],
                        'TTL': results[2],
                        'Currency': results[3],
                        'AmountPaid': results[4],
                        'AmountDue': results[5],
                        'State': results[6],
                    }
                
        except Exception as e:
            self.logger.error(f"GetOwedInfo error for drip_token: '{drip_token}', session_id: '{session_id}': {e}")
            if "ERR:" in str(e):
                error = str(e)
            else:
                error = "ERR: General System Error"
            resp_obj = {"Action" : "AmountDue", "Message": f"{error}"}

        return resp_obj


    def ProcessPayment(self, drip_token=None, amount=None, signature=None):
        """
            Process an incoming payment from the client
            1. Validate the signature
            2. Validate the amount against the ledger:
                - Must be equal or more then the amount due
                - Cannot be more then the max channel funding value
            3. Add the payment to the ledger table
            4. Add the payment to the payment table
            5. Update state of session to paid
        """
        resp_obj = {}
        try:
            self.logger.info(f"ProcessPayment for drip_token: '{drip_token}' for amount: '{amount}' signature: '{signature[:8]}...''")

            if drip_token is None:
                raise Exception("ERR: Missing drip token")
            if amount is None:
                raise Exception("ERR: Missing amount")
            if signature is None:
                raise Exception("ERR: Missing signature")
            
            # Fetch agreement information from the database
            agreement = mdefs.get_agreement(drip_token=drip_token)
            agreement_channel_id = agreement.channel_id
            agreement_client_public_key = agreement.client_public_key
            agreement_proposal_id = agreement.proposal_id

            # - Validate the signature
            valid = self.lts.verify_signature(signature=signature, channel_id=agreement_channel_id, amount=amount, public_key=agreement_client_public_key)
            if not valid:
                raise Exception("ERR: Invalid signature")
            
            # - Validate the amount against the ledger due
            ledger = mdefs.get_ledger_record(drip_token=drip_token)
            if not ledger:
                raise Exception("ERR: No valid ledger record found")
            
            ledger_total_due = ledger.total_due
            ledger_channel_balance = ledger.channel_balance
            ledger_total_paid = ledger.total_paid

            # Convert string to int for amount
            amount = int(amount)

            # - Validate the amount is equal to the amount due, but not more then the max channel funding
            invalid_amount_conditions = [
                # Check if the amount is less than the ledger's total due
                amount < ledger_total_due,
                # Check if the amount is greater than the ledger's channel balance
                amount > ledger_channel_balance,
                # Check if the amount is equal to the ledger's total paid
                amount <= ledger_total_paid
            ]

            if any(invalid_amount_conditions):
                self.logger.warning(f"ProcessPayment amount: '{amount}' is invalid for payment from drip_token: '{drip_token}'")
                raise Exception("ERR: Invalid amount for payment")

            # - If we made it here, we are good to add the payment to the ledger and the payment table
            mdefs.insert_payment(proposal_id=agreement_proposal_id, drip_token=drip_token, amount=amount, signature=signature)
            self.logger.info(f"ProcessPayment added in payment table, amount: '{amount}' for '{drip_token}'")

            # - Add the payment to the ledger table
            count = mdefs.add_ledger_payment(drip_token=drip_token, amount=amount)
            if count == 0:
                raise Exception("ERR: Failed to add payment to ledger table")
            
            # - Update the session based on the ledger state after inserting the payment
            # If a state is in a bad state, we need to ensure an update happens sooner then the cycle
            polling_interval = self.parser.getint('Terms', 'payment_polling_interval')
            count = mdefs.update_state_based_on_drip_token(drip_token=drip_token, polling_interval=polling_interval)
            if count == 0:
                raise Exception(f"ERR: Failed to ad-hoc session update state based on ledger state")
            
            resp_obj = {
                "Action": "PaymentAccepted",
                "Message": "Payment accepted"
            }

        except Exception as e:
            self.logger.error(f"ProcessPayment error processing incoming payment for drip_token: '{drip_token}' : {e}")
            if "ERR:" in str(e):
                error = str(e)
            else:
                error = "ERR: General System Error"
            resp_obj = {"Action" : "PaymentDenied", "Message": f"{error}"}
        
        return resp_obj


# - Private functions
    def _validate_refresh_agreement(self, payload=None):
        """
           Validate clients response to an refresh of the agreement
           We look at the JWT and ensure the TX they proposed is valid 
        """
        # Validate the inquiry payload and attributes are correct(present)
        error = None
        validated_object = {}
        try:
            required_keys = ["Action", "TXHash", "JWTPayload"]

            for key in required_keys:
                if key not in payload:
                    self.logger.error(f"RefreshAgreement payload verified, key not in payload '{key}'")
                    raise Exception("ERR: Missing required keys or values")
                
                if payload[key] is None or payload[key] == "":
                    self.logger.error(f"RefreshAgreement error, key value is None or empty for key: '{key}'")
                    raise Exception("ERR: Missing required keys or values")

            if payload["Action"] != "RefreshAgreement":
                self.logger.error(f"RefreshAgreement error, invalid action given: '{payload['Action']}'")
                raise Exception("ERR: Invalid action given")

            # Verify the JWT payload
            jwt_payload = payload["JWTPayload"]
            jwt_payload, error = self._verify_jwt(jwt_payload)
            self.logger.debug(f"RefreshAgreement payload verified output: '{json.dumps(jwt_payload, indent=4)}'")
            if error:
                raise Exception(error)

            # Ensure the TXHash is valid on the ledger, and contains the correct information
            # Get the TXHash from the payload (The payload is from the JWT token)
            tx_hash = payload["TXHash"]
            tx_details = self.lts.get_tx_details(tx_hash)
            parsed_tx = self.lts.parse_refresh_tx(tx_details)
            self.logger.debug(f"RefreshAgreement transaction details for '{tx_hash}' : '{json.dumps(parsed_tx, indent=4)}'")

            # Validate the TX against the payload, and ensure it is valid
            #   - Ensure the TX is valid
            if parsed_tx['validation'] != 'tesSUCCESS':
                self.logger.error(f"RefreshAgreement transaction validation failed: '{parsed_tx['validation']}'")
                raise Exception("ERR: TX was not tesSUCCESS")
            
            #MinChannelFunding
            if int(parsed_tx['amount']) != jwt_payload['MinChannelFunding']:
                raise Exception("ERR: Transaction amount does not match the refresh proposal value.")

            #SettlementDate
            if parsed_tx['expiration'] != jwt_payload['SettlementDate']:
                raise Exception("ERR: Transaction expiration does not match the refresh proposal value.")
            
            #DestinationAddress
            if parsed_tx['final_destination'] != self.parser.get('Wallet', 'classic_address'):
                raise Exception("ERR: Transaction destination does not match the refresh proposal value.")
            
            #ChannelID
            if parsed_tx['channel_id'] != jwt_payload['ChannelID']:
                raise Exception("ERR: Transaction channel ID does not match the refresh proposal value.")
            
            # We have validated the TX and the JWT payload, so lets return the details in a nice package
            validated_object['Action'] = "RefreshApproved"
            validated_object['TXPayload'] = parsed_tx
            validated_object['JWTPayload'] = jwt_payload

            # cleaned # _* denotes extracted from jwt and tx values. We can trust these values now.
            validated_object['_proposal_id'] = jwt_payload['ProposalID']
            validated_object['_drip_token'] = jwt_payload['DripToken']
            validated_object['_expires'] = self.lts.convert_epoch(jwt_payload['SettlementDate'])
            validated_object['_min_channel_funding'] = parsed_tx['amount']

            self.logger.debug(f"RefreshAgreement validated object: '{json.dumps(validated_object, indent=4)}'")

        except Exception as e:
            tbh = traceback.format_exc()
            self.logger.error(f"RefreshAgreement error verifying payload: '{tbh}'")
            error = e if str(e).startswith("ERR:") else "ERR: General System Error"
        
        return validated_object, error


    def _validate_agreement(self, payload=None):
        """
           Validate clients response to an inquiry, the agreement
           We look at the JWT and ensure the TX they proposed is valid 
        """
        # Validate the inquiry payload and attributes are correct(present)
        error = None
        validated_object = {}
        try:
            required_keys = ["Action", "TXHash", "JWTPayload"]

            for key in required_keys:
                if key not in payload:
                    self.logger.debug(f"Agreement payload verified, key not in payload '{key}'")
                    raise Exception("ERR: Missing required keys or values")
                
                if payload[key] is None or payload[key] == "":
                    self.logger.debug(f"Agreement error, key value is None or empty for key: '{key}'")
                    raise Exception("ERR: Missing required keys or values")

            if payload["Action"] != "Agreement":
                self.logger.debug(f"Agreement error, invalid action given: '{payload['Action']}'")
                raise Exception("ERR: Invalid action given")

            # Verify the JWT payload
            jwt_payload = payload["JWTPayload"]
            jwt_payload, error = self._verify_jwt(jwt_payload)
            self.logger.debug(f"Agreement payload verified output: '{json.dumps(jwt_payload, indent=4)}'")
            if error:
                raise Exception(error)

            # Ensure the TXHash is valid on the ledger, and contains the correct information
            # Get the TXHash from the payload (The payload is from the JWT token)
            tx_hash = payload["TXHash"]
            tx_details = self.lts.get_tx_details(tx_hash)
            parsed_tx = self.lts.parse_channel_tx(tx_details)
            self.logger.debug(f"Agreement transaction details for '{tx_hash}' : '{json.dumps(parsed_tx, indent=4)}'")

            # Validate the TX against the payload, and ensure it is valid
            # - Ensure the TX contains a memo which matches the JWT proposal_id value
            if 'memo' not in parsed_tx:
                raise Exception("ERR: Transaction does not contain a memo")
            
            # - Ensure the TX memo matches the proposal ID
            if parsed_tx['memo'] != jwt_payload['ProposalID']:
                raise Exception("ERR: Transaction memo does not match the proposal")

            #   - Ensure the TX is valid
            if parsed_tx['validation'] != 'tesSUCCESS':
                self.logger.error(f"Agreement transaction validation failed: '{parsed_tx['validation']}' for '{tx_hash}'")
                raise Exception("ERR: TX was not tesSUCCESS")
            
            # Ensure the TX happened in the correct window of time
            inquiry_expiration = self.parser.getint('Terms', 'inquiry_expiration')
            tx_created = jwt_payload['exp'] - inquiry_expiration
            # - Ledger transaction happend after the issued JWT token
            if not parsed_tx['date'] > tx_created:
                raise Exception("ERR: Transaction happened before the JWT token was issued")
            
            # - Ensure the TX settle_delay is greater than the current time - 180 seconds / 3 minutes
            expired_window = self.parser.getint('SchedulesAndSettings', 'expired_window_seconds', fallback=180)
            if (parsed_tx["date"] + parsed_tx['settle_delay']) <= (int(time.time()) - expired_window):
                raise Exception("ERR: Transaction settle delay is not greater or near than the current epoch")

            # - Ensure cancel_after is NOT set on the payment channel
            # -- If cancel_after is set, we cannot continue to fund the channel for long periods of time
            if 'cancel_after' in parsed_tx:
                raise Exception("ERR: cancel_after is not allowed on the payment channel")
                
            # Ensure the TX matches the terms of the drip server TX vs the JWT token
            # - Ensure the channel funding is eq to the minimum channel funding
            if int(parsed_tx['amount']) != self.parser.getint('Terms', 'min_channel_funding'):
                raise Exception("ERR: Transaction amount not eq to minimum channel funding requirement")
            
            # - Ensure the settle_delay is eq to the channel_expiration
            if parsed_tx['settle_delay'] != self.parser.getint('Terms', 'channel_expiration'):
                raise Exception("ERR: Transaction settle delay is not equal to the channel expiration")
            
            # - Esnure the destination address is the same as the drip server address
            if parsed_tx['destination'] != self.parser.get('Wallet', 'classic_address'):
                raise Exception("ERR: Transaction destination address is not equal to the drip server address")
            
            # Ensure Rate is set if the payment type is TimeBased or Both
            if jwt_payload['PaymentType'] in ["TimeBased", "Both"]:
                if jwt_payload['Rate'] == 0:
                    raise Exception("ERR: Invalid rate caclulated")
                
            # - Ensure, if set, the destination tag is the same as the drip server address (config.ini or JWT, in that order)
            # - We may want dynamic destination tags, so allow the JWT to override the config.ini by not setting the config.ini value
            settings_dtag = self.parser.getint('Terms', 'destination_tag', fallback=False)
            if settings_dtag or 'DestinationTag' in jwt_payload:
                if settings_dtag:
                    dtag = settings_dtag
                else:
                    dtag = jwt_payload['DestinationTag']

                if 'destination_tag' not in parsed_tx:
                    raise Exception("ERR: Invalid destination tag")

                if parsed_tx['destination_tag'] != dtag:
                    raise Exception("ERR: Invalid destination tag")
                
            elif 'destination_tag' in parsed_tx:
                raise Exception("ERR: Invalid destination tag")

            # We have validated the TX and the JWT payload, so lets return the details in a nice package
            validated_object['Action'] = "ConfirmationApproved"
            validated_object['TXPayload'] = parsed_tx
            validated_object['JWTPayload'] = jwt_payload
            
            # cleaned # _* denotes extracted from jwt and tx values. We can trust these values now.
            validated_object['_proposal_id'] = jwt_payload['ProposalID']
            validated_object['_drip_token'] = jwt_payload['DripToken']
            validated_object['_domain'] = jwt_payload['Domain']
            validated_object['_expires'] = int(parsed_tx['date']) + int(parsed_tx['settle_delay'])
            validated_object['_rate'] = jwt_payload['Rate']
            validated_object['_payment_type'] = jwt_payload['PaymentType']
            validated_object['_polling_interval'] = jwt_payload['PollingInterval']
            validated_object['_min_channel_funding'] = parsed_tx['amount']
            validated_object['_settlement_delay'] = parsed_tx['settle_delay']
            validated_object['_target_currency'] = "XRP"  # Future use
            validated_object['_client_address'] = parsed_tx['account']
            validated_object['_client_public_key'] = parsed_tx['publickey']
            validated_object['_channel_id'] = parsed_tx['channel_id']

            self.logger.debug(f"Agreement payload output: '{json.dumps(validated_object, indent=4)}'")

        except Exception as e:
            tbh = traceback.format_exc()
            self.logger.error(f"Agreement error verifying payload: '{tbh}'")
            error = e if str(e).startswith("ERR:") else "ERR: General System Error"
        
        return validated_object, error


    def _accept_client_agreement(self, validated_object=None):
        """
        Accepts an Agreement between the client and server in the database

        :param validated_object: The validated object from the client inquiry
        :type validated_object: dict

        :return: The database response and an error message if any otherwise None
        """
        error = None
        create_response = {}
        try:
            # Pre-checks
            if validated_object is None:
                raise Exception("ERR: Invalid validated object")
            if 'Action' not in validated_object:
                self.logger.error("AcceptAgreement error creating agreement: 'Action' not in validated object")
                raise Exception("ERR: Invalid validated object")
            if validated_object['Action'] != "ConfirmationApproved":
                self.logger.error(f"AcceptAgreement error creating client agreement: '{validated_object['Action']}' is not 'ConfirmationApproved'")
                raise Exception("ERR: Invalid validated object")

            # Ensure all fields are present
            required_keys = ["TXPayload", "JWTPayload",
                             "_drip_token", "_domain", "_expires", "_payment_type", "_polling_interval", 
                             "_min_channel_funding", "_settlement_delay", "_target_currency", "_rate", 
                             "_client_address", "_client_public_key", "_channel_id", "_proposal_id"]
            
            for key in required_keys:
                if key not in validated_object:
                    self.logger.error(f"AcceptAgreement error creating client agreement: '{key}' not in validated object")
                    raise Exception("ERR: Invalid validated object")
                
                if validated_object[key] is None or validated_object[key] == "":
                    self.logger.error(f"AcceptAgreement error creating client agreement: '{key}' is None or empty")
                    raise Exception("ERR: Invalid validated object")
                

            # Fetch session id from session table
            session_id = mdefs.get_session(drip_token=validated_object['_drip_token'])

            # Create the agreement in the database
            submit_object = {
                'proposal_id': validated_object['_proposal_id'],
                'session_id': session_id.session_id,
                'drip_token': validated_object['_drip_token'], 
                'domain': validated_object['_domain'],
                'expires': validated_object['_expires'],
                'payment_type': validated_object['_payment_type'],
                'polling_interval': validated_object['_polling_interval'], 
                'min_channel_funding': validated_object['_min_channel_funding'],
                'settlement_delay': validated_object['_settlement_delay'],
                'target_currency': validated_object['_target_currency'], 
                'client_address': validated_object['_client_address'], 
                'client_public_key': validated_object['_client_public_key'],
                'channel_id': validated_object['_channel_id'],
                'rate': validated_object['_rate']
            }

            # Will raise error on failure
            mdefs.new_agreement(**submit_object)
            self.logger.debug(f"AcceptAgreement creating agreement with: '{json.dumps(submit_object, indent=2, sort_keys=True)}'")

            create_response = {
                "Action": "AgreementAccepted",
                "DripToken": validated_object['_drip_token'],
                "ProposalID": validated_object['_proposal_id'],
                "ChannelID": validated_object['_channel_id'],
                "Expires": validated_object['_expires'],
                "Message": "Agreement accepted"
            }

            # Add a rate field if appropriate
            if validated_object['_payment_type'] in ["TimeBased", "Both"]:
                create_response['Rate'] = validated_object['_rate']

            # Add Client Wallet Address to session, Server can use it as USERID / UNIQUEID
            mdefs.update_client_address_state_session(drip_token=validated_object['_drip_token'], client_address=validated_object['_client_address'])
            
            self.logger.debug(f"AcceptAgreement created response: '{json.dumps(create_response, indent=2, sort_keys=True)}'")


        except Exception as e:
            self.logger.error(f"AcceptAgreement error creating client payment session: {e}")
            error = { "Action" : "AgreementDenied", "Message": "ERR: General System Error"}
        
        return create_response, error
    

    def _get_parser(self):
        # Let's get the configuration file and read it
        config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config.ini'))
        self.logger.debug(f"GetParser reading configuration file from: '{config_path}'")
        config = configparser.ConfigParserCrypt()
        return config.config_read(config_path)


    def _generate_jwt(self, payload, ttl=None, algorithm='ES256'):
        """
        Generates a JWT token from a given payload and shared key.
        
        :param payload: The payload as a python dictionary
        :param ttl: Time-to-live in seconds (optional)
        :param algorithm: The algorithm to be used for the JWT signature (default is 'HS256')
        
        :return: JWT token as a string
        """
        # Get signing key
        token = None
        error = None
        try:
            if self._payload_secret is None:
                self._payload_secret = self.parser.get('System', 'jwt_private_encrypted')
            if ttl:
                payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(seconds=ttl)
            token = jwt.encode(payload, self._payload_secret, algorithm=algorithm)

        except Exception as e:
            self.logger.error(f"GenerateJWT error generating token: {e}")
            error = "ERR: Unknown error during token generation"
        
        return token, error


    def _verify_jwt(self, token, algorithms=['ES256']):
        """
        Verifies a JWT token and returns the payload.

        :param token: The JWT token as a string
        :param algorithms: The algorithms to be used for the JWT signature (default is 'ES256')

        :return: The payload as a python dictionary and an error message if any otherwise None
        """
        payload = None
        error = None
        try:
            if self._payload_public is None:
                self._payload_public = self.parser.get('System', 'jwt_public_encrypted')
            
            payload = jwt.decode(token, self._payload_public, algorithms=algorithms)

        except jwt.ExpiredSignatureError:
            error = "ERR: Token has expired"
            self.logger.error(f"VerifyJWT error verifying payload: {error}")
        except jwt.InvalidTokenError:
            error = "ERR: Invalid token"
            self.logger.error(f"VerifyJWT error verifying  payload: {error}")
        except Exception as e:
            self.logger.error(f"VerifyJWT error verifying  payload: {e}")
            error = "ERR: Unknown error during validation"
        
        return payload, error


    def _increment_time_based_rates(self):
        """
            Increments the rates for time based payments
        """
        try:
            # - For time based payments, add rate to the balance due.
            # - For this reason, this should run in sync with the polling frequency
            affected_count = mdefs.inc_rates_on_ledger()
            self.logger.info(f"Increment time based rates updated '{affected_count}' balances on ledger table")
        
        except Exception:
            tbe = traceback.format_exc()
            self.logger.error(f"Increment time based rates error during update of ledger table: {tbe}")
            return False


    def _update_ledger_state(self):
        """
            Runs calculations on the ledger table
        """
        try:
            # - Update session state based on state of the ledger
            polling_interval = self.parser.getint('Terms', 'payment_polling_interval', fallback=60)
            affected_count = mdefs.update_state_based_on_ledger(polling_interval=polling_interval)
            self.logger.info(f"Update ledger state for '{affected_count}' sessions")

            # - Update counters for who is past due
            past_due = mdefs.inc_past_due_on_ledger(polling_interval=polling_interval)
            self.logger.debug(f"Update ledger by incrementing '{past_due}' past due counters")

        except Exception:
            tbe = traceback.format_exc()
            self.logger.error(f"Update ledger error: {tbe}")
            return False


    def _claim_worker(self, drip_token):
        """
        Claim for a single drip_token.

        :param drip_token: The drip token to claim for
        :type drip_token: str

        :return: The drip token and a boolean indicating success or failure
        """
        response = drip_token, False
        try:
            self.logger.info(f"Claim channel worker on drip_token: '{drip_token}'")

            # - Freeze the activity by setting each record in each table as destroyed
            try:
                mdefs.set_to_destroy(drip_token=drip_token)
            except Exception as e:
                self.logger.error(f"Claim channel worker error on drip_token: '{drip_token}', record to be destroyed: {e}")

            # - get important claim information from database, if it exists
            claim_info = mdefs.get_channel_information(drip_token=drip_token)
            if not claim_info:
                self.logger.warning(f"No claim channel information found for drip_token: {drip_token}, may of never paid.")
                return drip_token, True


            # - Extract Claim information 
            amount = claim_info.amount
            signature = claim_info.signature
            client_address = claim_info.client_address
            client_public_key = claim_info.client_public_key
            channel_id = claim_info.channel_id
            self.logger.debug(f"Claim channel woker information for drip_token: '{drip_token}' claim : '{claim_info}'")

            # - Attempt to make the claim against the channel
            claim_response, claim_error = self.lts.make_channel_claim(channel_id=channel_id, 
                                                        amount=amount, 
                                                        signature=signature, 
                                                        public_key=client_public_key)
            
            no_target_error = False
            if claim_error:
                if "tecNO_TARGET" in claim_error:
                    no_target_error = True
                    self.logger.warning(f"Claim channel worker error executing claim: '{drip_token}' : '{claim_error}', will remove from database")
                else:    
                    raise Exception(claim_error)
                
            tx_hash = None
            tx_result = None
            if not no_target_error:
                # Extract TransactionResult
                try: 
                    if 'meta' in claim_response:
                        if 'TransactionResult' in claim_response['meta']:
                            tx_result = claim_response['meta']['TransactionResult']
                
                    # Extract hash
                    if 'hash' in claim_response:
                        tx_hash = claim_response['hash']

                except Exception as e:
                    self.logger.error(f"Claim channel worker error executing claim: '{drip_token}' : '{e}'")
                    claim_response = "Error during claim response processing"
            else:
                claim_response = "No target found for claim, error encounterd 'tecNO_TARGET'"

            # Craft a record of the claim
            rec = {
                    "drip_token": drip_token,
                    "client_address": client_address,
                    "channel_id": channel_id,
                    "amount": amount,
                    "claim_info": str(claim_info),
                    "claim_response": str(claim_response),
                    "tx_result": str(tx_result),
                    "tx_hash": str(tx_hash)
            }

            # Ensure we can write out the claim information to a file
            # - Check if the 'claims' directory exists and create it if not
            claims_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'claims'))
            if not os.path.exists(claims_dir):
                self.logger.warning(f"Claim channel worker claims directory does not exist, creating: '{claims_dir}'")
                os.makedirs(claims_dir)

            # - Check if the 'failed_claims' directory exists and create it if not
            failed_claims_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'failed_claims'))
            if not os.path.exists(failed_claims_dir):
                self.logger.warning(f"Claim channel worker failed claims directory does not exist, creating: '{failed_claims_dir}'")
                os.makedirs(failed_claims_dir)      

            # Create the file and write out the claim information
            filename = f"{drip_token}_claim.log"
            if no_target_error:
                claims_path = os.path.join(failed_claims_dir, filename)
            else:
                claims_path = os.path.join(claims_dir, filename)    

            # Write out to a file a log of the claim, so we have a record for long term use
            with open(claims_path, 'w') as fx:
                json.dump(rec, fx, indent=2, sort_keys=True)

            response = drip_token, True

        except Exception:
            tbe = traceback.format_exc()
            self.logger.error(f"Claim channel worker error claiming for drip_token: '{drip_token}': '{tbe}'")
            
        return response


    def _claim_and_clean(self, flush=False):
        """
            Runs the claim and clean process
        """
        try:
            self.logger.info("Claim and Clean process started")

            # Get sessions marked for destruction
            if flush:
                self.logger.warning("Claim and Clean shutdown, flushing all agreements and claims")
                exp_sessions = mdefs.flush_all_agreements()
            else:
                exp_sessions = mdefs.get_and_set_destroyed_agreements()
            
            self.logger.info(f"Claim and Clean found '{len(exp_sessions)}' sessions, marked for claiming")
            
            # Directly call the _claim_worker for each session
            for session in exp_sessions:
                self.logger.debug(f"Claim and Clean marking drip_token: '{session}' for destruction.")
                
                result = self._claim_worker(session)  # Directly call the _claim_worker function

                drip_token, success = result
                # Remove the associated records from the database tables
                if success:
                    self.logger.info(f"Claim and Clean claimed drip_token: '{drip_token}' channel, removing records")
                    mdefs.delete_agreement_record(drip_token=drip_token)
                    mdefs.delete_session_record(drip_token=drip_token)
                    mdefs.delete_ledger_record(drip_token=drip_token)
                    mdefs.delete_payment_record(drip_token=drip_token)
                else:
                    # If not successful, leave the records in place and log warning
                    self.logger.warning(f"Claim and Clean failed to claim drip_token: '{drip_token}' channel, leaving records")

        except Exception:
            tbe = traceback.format_exc()
            self.logger.error(f"Claim and Clean error running process: {tbe}")
        return False


    def _past_due_kicker(self):
        """
            Runs the past due kicker query, logs results
        """
        try:
            cnt = mdefs.past_due_kicker()
            self.logger.info(f"Past due kicker process completed, '{cnt}' sessions updated")

        except Exception:
            tbe = traceback.format_exc()
            self.logger.error(f"Past due kicker error in process: {tbe}")
            return False
        

    def _offload_to_coldwallet(self):
        """
            Pass through the offload to coldwallet function as apart of the Drip Engine session
            Needed for thread locking / session association
        """
        self.lts._offload_to_coldwallet()