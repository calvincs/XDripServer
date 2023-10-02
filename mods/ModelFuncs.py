from .Models import Session, Agreement, Ledger, Payment
from . import ConfigParserCrypt as configparser
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import IntegrityError
from sqlalchemy import and_, case, update, text,  delete
from datetime import datetime, timedelta
import os
import time
import logging
from .DatabaseConnect import DBSession

#Cleaned up logging

# Let's get the configuration file and read it
config = configparser.ConfigParserCrypt()
config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config.ini'))
parser = config.config_read(config_path)  # Read the configuration file

# Set up logging
logger = logging.getLogger("xdrip.ModelFuncs")


def new_session(session_id=None, drip_token=None, domain=None, uri=None):
    """
    Create a new session.

    :param session: Database session
    :param session_id: Unique session id from website/app
    :param drip_token: Unique token for the user's Drip client session
    :param domain: Domain of the website/app
    :param uri: URI of the website/app

    :return: Newly created Session object w/ new drip_token id
    """
    if not session_id or not domain or not uri or not drip_token:
        raise Exception("Missing required fields")

    with DBSession() as session:
        try:
            new_session = Session(
                session_id=session_id,
                drip_token=drip_token,
                domain=domain,
                uri=uri
            )
            session.add(new_session)
            session.commit()
            session.close()

            return new_session
        
        except IntegrityError as e:
            logger.warning(f"Session already exists for session_id: {session_id} or drip_token: {drip_token}")
            session.rollback()
            raise e
        
        except Exception as e:
            logger.error(f"Error in new_session: {e}")
            session.rollback()
            raise e
    

def get_session(session_id=None, drip_token=None):
    """
    Get a session.

    :param session: Database session
    :param session_id: Unique session id from website/app
    :param drip_token: Unique drip token id from drip client

    :return: Session object
    """
    if not session_id and not drip_token:
        raise Exception("Must provide either session_id or drip_token")

    with DBSession() as session:
        try:
            query = session.query(Session)

            if session_id:
                query = query.filter(Session.session_id == session_id)

            elif drip_token:
                query = query.filter(Session.drip_token == drip_token)
            
            return query.first()  # Return the Session object
        except NoResultFound:
            logger.warning(f"No session found for session_id: {session_id} or drip_token: {drip_token}")
            raise Exception("No session found")
        except Exception as e:
            logger.error(f"Error in get_session: {e}")
            raise e


def update_payment_state(drip_token=None, payment_state=None):
    """
    Update the payment state of a session.

    :param session: Database session
    :param payment_state: New payment state
    :param drip_token: Unique drip token id from drip client

    :return: Number of updated entries
    """
    if not drip_token:
        raise Exception("Must provide drip_token")
    if not payment_state:
        raise Exception("Must provide payment_state")
    
    payment_state = payment_state.lower()
    if payment_state not in ['init', 'paid', 'pending', 'overdue', 'nsf', 'error', 'expired']:
        raise Exception("Invalid payment state provided")

    updated_count = 0
    with DBSession() as session:
        try:
            query = session.query(Session)
            query = query.filter(Session.drip_token == drip_token)
            updated_count = int(query.update({'payment_state': payment_state}))

            session.commit()

            return updated_count
        
        except Exception as e:
            logger.error(f"Error in update_payment_state: {e}")
            session.rollback()
            raise e


def update_client_address_state_session(drip_token=None, client_address=None):
    """
    Update the client_address field for the session with the given drip_token.
    :param drip_token: The drip_token to search for.
    :param client_address: The new address to set for client_address.
    :return: The updated Session object.
    """

    with DBSession() as session:
        try:
            # Query the session with the matching drip_token
            updates = session.query(Session).filter(Session.drip_token == drip_token).first()

            # If session is found, update the client_address
            if updates:
                updates.client_address = client_address
                updates.payment_state = 'pending'

                session.commit()
                return updates
            else:
                return None
            
        except Exception as e:
            logger.warning(f"Error in update_client_address_state_session: {e}")
            session.rollback()
            raise e


def new_agreement(**kwargs):
    """
        Create a new agreement.

        :param session: Database session

        **kwargs:
        - session_id: Unique session id from website/app
        - drip_token: Unique token for the user's Drip client session
        - domain: Domain of the website/app
        - expires: Expiration time for the proposal
        - payment_type: Payment type (TimeBased, UnitBased, Both)
        - polling_interval: Polling interval in seconds
        - min_channel_funding: Minimum amount of XRP Drops for channel funding
        - settlement_delay: Settlement delay in seconds
        - target_currency: Target currency (USD, EUR, BTC, etc.)
        - rate: The rate of the Agreement to be paid every cycle, if applicable
        - client_address: XRP Classic address
        - client_public_key: XRP Classic public key
        - channel_id: XRP Classic Payment Channel ID
        :return: Newly created Agreement object id -> proposal_id
    """

    # List of required fields
    required_fields = [
        'drip_token', 'domain', 'expires', 'payment_type', 'session_id',  
        'polling_interval', 'min_channel_funding', 'settlement_delay', 'rate',
        'target_currency', 'client_address', 'client_public_key', 'channel_id'
    ]
    # Check that all required fields are provided
    for field in required_fields:
        if field not in kwargs:
            raise ValueError(f"Missing required field: {field}")

    agreement = None

    with DBSession() as session:
        try:
            # Create Agreement object
            agreement = Agreement(
                proposal_id=kwargs['proposal_id'],
                drip_token=kwargs['drip_token'],
                session_id=kwargs['session_id'],
                domain=kwargs['domain'],
                expires=kwargs['expires'],
                payment_type=kwargs['payment_type'],
                polling_interval=kwargs['polling_interval'],
                min_channel_funding=kwargs['min_channel_funding'],
                settlement_delay=kwargs['settlement_delay'],
                rate=kwargs['rate'],
                target_currency=kwargs['target_currency'],
                client_address=kwargs['client_address'],
                client_public_key=kwargs['client_public_key'],
                channel_id=kwargs['channel_id']
            )

            # Add to the session
            session.add(agreement)
            session.commit()

            return agreement  # Return the newly created Agreement object

        except Exception as e:
            logger.error(f"Error in new_agreement: {e}")
            session.rollback()
            raise e


def refresh_agreement(**kwargs):
    # List of required fields
    required_fields = ['proposal_id', 'drip_token', 'min_channel_funding', 'expires']
    # Check that all required fields are provided
    for field in required_fields:
        if field not in kwargs:
            raise ValueError(f"Missing required field: {field}")
        
    with DBSession() as session:
        try:
            # Update the Agreement table
            agreement_query = text("""UPDATE agreements SET min_channel_funding = :min_channel_funding, expires = :expires 
                                      WHERE proposal_id = :proposal_id AND drip_token = :drip_token""")
            
            results = session.execute(agreement_query, { 'min_channel_funding' : kwargs['min_channel_funding'], 'expires' : kwargs['expires'], 
                                                        'proposal_id' : kwargs['proposal_id'], 'drip_token' : kwargs['drip_token']})

            # Update the Ledger table
            ledger_query = text("UPDATE ledger SET channel_balance = :min_channel_funding, refresh_counter = refresh_counter + 1 WHERE drip_token = :drip_token")
            session.execute(ledger_query, { 'min_channel_funding' : kwargs['min_channel_funding'], 'drip_token' : kwargs['drip_token']})

            # Commit the transaction
            session.commit()

            return results.rowcount
        
        except Exception as e:
            logger.error(f"Error in refresh_agreement: {e}")
            session.rollback()
            raise e


def get_agreement(proposal_id=None, drip_token=None):
    """
    Get an agreement by proposal_id or drip_token
    :param session: Database session
    :param proposal_id: Proposal GUID
    :param drip_token: Drip Token
    :return: Agreement object
    """
    if proposal_id is None and drip_token is None:
        raise ValueError("Must provide either proposal_id or drip_token")
    
    with DBSession() as session:
        try:
            query = session.query(Agreement)
            record = None

            if proposal_id is not None:
                record = query.filter(Agreement.proposal_id == proposal_id).first()

            if drip_token is not None:
                record = query.filter(Agreement.drip_token == drip_token).first()

            if not record:
                logger.warning(f"No Agreement record found for proposal_id: {proposal_id} or drip_token: {drip_token}")
                raise ValueError("No record found")

            return record
        
        except Exception as e:
            logger.error(f"Error in get_agreement: {e}")
            raise e


def new_ledger_record(**kwargs):
    """
    Create a new ledger record for tracking payments
    :param proposal_id: Proposal GUID
    :param drip_token: Drip Token
    :param channel_balance: Channel Balance
    :param rate: Rate
    :param payment_type: Payment Type
    :return: Ledger object
    """
    required_fields = ['proposal_id', 'drip_token', 'channel_balance', 'rate', 'payment_type']
    for field in required_fields:
        if field not in kwargs:
            raise ValueError(f"Missing required field: {field}")
        if kwargs[field] is None:
            raise ValueError(f"Missing required field value: {field}")

    with DBSession() as session:
        try:
            new_ledger = Ledger(
                proposal_id=kwargs['proposal_id'],
                drip_token=kwargs['drip_token'],
                channel_balance=kwargs['channel_balance'],
                rate=kwargs['rate'],
                payment_type=kwargs['payment_type']
            )
            session.add(new_ledger)
            session.commit()

            return new_ledger  # Return the newly created Ledger object
        
        except Exception as e:
            logger.error(f"Error in new_ledger_record: {e}")
            session.rollback()
            raise e


def get_ledger_record(drip_token=None, proposal_id=None):
    """
    Get a ledger record by drip_token or proposal_id
    :param session: Database session
    :param drip_token: Drip Token
    :param proposal_id: Proposal GUID
    :return: Ledger object
    """
    if drip_token is None and proposal_id is None:
        raise ValueError("Must provide either drip_token or proposal_id")

    with DBSession() as session:
        try:
            query = session.query(Ledger).filter(Ledger.destroyed == False)
            if drip_token is not None:
                query = query.filter(Ledger.drip_token == drip_token)
            if proposal_id is not None:
                query = query.filter(Ledger.proposal_id == proposal_id)

            return query.first()
        
        except NoResultFound:
            logger.warning(f"No record found for drip_token: {drip_token} or proposal_id: {proposal_id}")
            raise Exception("No record found")
        
        except Exception as e:
            logger.error(f"Error in get_ledger_record: {e}")
            raise e
        

def add_ledger_payment(drip_token=None, proposal_id=None, amount=None):
    """
    Update the ledger record with a payment amount using raw SQL executed with SQLAlchemy.

    :param drip_token: Drip Token
    :param proposal_id: Proposal GUID
    :param amount: Amount of Drip Tokens
    """
    if drip_token is None and proposal_id is None:
        raise ValueError("Must provide either drip_token or proposal_id")
    
    if amount is None:
        raise ValueError("Must provide amount")

    with DBSession() as session:
        try:
            # Define conditions based on provided parameters
            conditions = "destroyed = FALSE"
            params = {'amount': amount}
            
            if drip_token:
                conditions += " AND drip_token = :drip_token"
                params['drip_token'] = drip_token
            if proposal_id:
                conditions += " AND proposal_id = :proposal_id"
                params['proposal_id'] = proposal_id

            # Construct the raw SQL query
            sql_query = text(f"""
                UPDATE ledger
                SET total_paid = :amount, last_payment_timestamp = timezone('utc', NOW())
                WHERE {conditions}
            """)
            
            # Execute the query
            result = session.execute(sql_query, params)
            session.commit()

            # Return the number of rows affected
            return result.rowcount
        
        except Exception as e:
            logger.error(f"Error in add_ledger_payment: {e}")
            session.rollback()
            raise e


def inc_rates_on_ledger():
    """
    Increment the rates on the ledger based on the rates in the table.
    This should be executed every polling cycle.

    IF the channel balance is less than the total due, skip the record.
    IF adding the rate to the total_due would exceed the channel balance, set total_due to channel_balance.
    If marked as destroyed, skip the record.

    :param session: Database session

    :return: Update query
    """
    with DBSession() as session:
        try:
            update_query = (
                update(Ledger)
                .where(
                    and_(
                        Ledger.payment_type.in_(['TimeBased', 'Both']),
                        Ledger.channel_balance > Ledger.total_due,
                        Ledger.destroyed == False
                    )
                )
                .values(
                    total_due=case(
                        (
                            Ledger.channel_balance < Ledger.total_due + Ledger.rate,
                            Ledger.channel_balance
                        ),
                        else_=Ledger.total_due + Ledger.rate
                    )
                )
            )

            # Execute the query
            result = session.execute(update_query)

            # Commit the transaction
            session.commit()

            return result.rowcount
        
        except Exception as e:
            logger.error(f"Error in inc_rates_on_ledger: {e}")
            session.rollback()
            raise e


def update_state_based_on_drip_token(drip_token, polling_interval=60):
    """
    Updates the payment state for a specific drip_token in the 'sessions' table based on data from the 'ledger' and 'agreements' tables.
    
    Args:
        drip_token (str): The drip_token to update the payment state for.
        polling_interval (int): The interval in seconds used to determine the 'overdue' and 'pending' states.
        
    Returns:
        int: The number of rows affected.
    """
    # Check if drip_token is provided
    if not drip_token:
        raise ValueError("Must provide drip_token")

    current_time = datetime.utcnow()
    expired_window_seconds = parser.getint('SchedulesAndSettings', 'expired_window_seconds', fallback=180)
    epoch_expired = int(time.time() + expired_window_seconds)

    with DBSession() as session:
        try:
            # Construct the raw SQL query using CASE WHEN logic
            sql_query = text("""
                UPDATE sessions
                SET payment_state = CASE 
                    WHEN agreements.expires <= :epoch_expired THEN 'expired'::payment_state_enum
                    WHEN ledger.channel_balance <= ledger.total_due THEN 'nsf'::payment_state_enum
                    WHEN ledger.total_due <= ledger.total_paid THEN 'paid'::payment_state_enum
                    WHEN ledger.total_due > ledger.total_paid AND 
                         ledger.last_payment_timestamp < :last_payment_timestamp_overdue THEN 'overdue'::payment_state_enum
                    WHEN ledger.total_due > ledger.total_paid AND 
                         ledger.last_payment_timestamp > :last_payment_timestamp_pending AND
                         ledger.last_payment_timestamp <= :current_time THEN 'pending'::payment_state_enum
                    ELSE 'error'::payment_state_enum
                END
                FROM ledger, agreements
                WHERE 
                    sessions.drip_token = :drip_token AND 
                    sessions.drip_token = ledger.drip_token AND 
                    sessions.drip_token = agreements.drip_token AND 
                    sessions.destroyed = FALSE
            """)
            
            # Define the parameters for the SQL query
            params = {
                'drip_token': drip_token,
                'epoch_expired': epoch_expired,
                'last_payment_timestamp_overdue': current_time - timedelta(seconds=polling_interval),
                'last_payment_timestamp_pending': current_time - timedelta(seconds=polling_interval),
                'current_time': current_time
            }

            # Execute the query
            result = session.execute(sql_query, params)
            session.commit()

            # Return the number of rows affected
            return result.rowcount
        
        except Exception as e:
            logger.error(f"Error in update_state_based_on_drip_token: {e}")
            session.rollback()
            raise e


def update_state_based_on_ledger(polling_interval=60):
    """
    Updates the payment state in the 'sessions' table based on data from the 'ledger' and 'agreements' tables.
    
    Args:
        polling_interval (int): The interval in seconds used to determine the 'overdue' and 'pending' states.
        
    Returns:
        int: The number of rows affected.
    """
    current_time = datetime.utcnow()
    expired_window_seconds = parser.getint('SchedulesAndSettings', 'expired_window_seconds', fallback=180)
    epoch_expired = int(time.time() + expired_window_seconds)
    
    with DBSession() as session:
        try:
            # Construct the raw SQL query using CASE WHEN logic
            sql_query = text("""
                UPDATE sessions
                SET payment_state = CASE 
                    WHEN agreements.expires <= :epoch_expired THEN 'expired'::payment_state_enum
                    WHEN ledger.channel_balance <= ledger.total_due THEN 'nsf'::payment_state_enum
                    WHEN ledger.total_due <= ledger.total_paid THEN 'paid'::payment_state_enum
                    WHEN ledger.total_due > ledger.total_paid AND 
                         ledger.last_payment_timestamp < :last_payment_timestamp_overdue THEN 'overdue'::payment_state_enum
                    WHEN ledger.total_due > ledger.total_paid AND 
                         ledger.last_payment_timestamp > :last_payment_timestamp_pending AND
                         ledger.last_payment_timestamp <= :current_time THEN 'pending'::payment_state_enum
                    ELSE 'error'::payment_state_enum
                END
                FROM ledger, agreements
                WHERE 
                    sessions.drip_token = ledger.drip_token AND 
                    sessions.drip_token = agreements.drip_token AND 
                    sessions.destroyed = FALSE
            """)
            
            # Define the parameters for the SQL query
            params = {
                'epoch_expired': epoch_expired,
                'last_payment_timestamp_overdue': current_time - timedelta(seconds=polling_interval),
                'last_payment_timestamp_pending': current_time - timedelta(seconds=polling_interval),
                'current_time': current_time
            }

            # Execute the query
            result = session.execute(sql_query, params)
            session.commit()

            # Return the number of rows affected
            return result.rowcount
        
        except Exception as e:
            logger.error(f"Error in update_state_based_on_ledger: {e}")
            session.rollback()
            raise e


def inc_past_due_on_ledger(polling_interval=60):
    # Update the Ledger table to increment the past_due_counter for overdue payments
    # - Will also increment if nsf state, as the wallet is not able to pay any future polls or unit debts

    with DBSession() as session:
        try:
            query = text("""
                UPDATE Ledger
                SET past_due_counter = past_due_counter + 1
                WHERE
                    (last_payment_timestamp < (CURRENT_TIMESTAMP AT TIME ZONE 'UTC') - INTERVAL ':interval seconds' AND destroyed = FALSE)
                    OR
                    (total_due = channel_balance AND destroyed = FALSE);
            """)
            result = session.execute(query, {'interval': polling_interval})
            
            # Commit the transaction
            session.commit()
            
            return result.rowcount

            return 0

        except Exception as e:
            logger.error(f"Error in inc_past_due_on_ledger: {e}")
            session.rollback()
            raise e


def ledger_preapproval(drip_token, amount):
    """
    Need to validate conditions of the ledger before approving a purchase against.
    :param session: Database session
    :param drip_token: Drip Token
    :param amount: Amount of Drip Tokens
    """
    with DBSession() as session:
        try:
            result = session.execute(text(
                """
                SELECT total_due, channel_balance, payment_type, 
                    CASE
                        WHEN (payment_type IN ('TimeBased', 'Both') AND total_due + rate + :amount > channel_balance) THEN 'exceeds'
                        WHEN (payment_type = 'UnitBased' AND total_due + :amount > channel_balance) THEN 'exceeds'
                        ELSE 'within_limit'
                    END AS balance_check
                FROM ledger
                WHERE drip_token = :drip_token;
                """),
                {'drip_token': drip_token, 'amount': amount}
            )

            return result.first()
    
        except Exception as e:
            logger.error(f"Error in ledger_preapproval: {e}")
            raise e


def ledger_add_unitdebt(drip_token, amount):
    """
    Add a unit debt to the ledger
    :param session: Database session
    :param drip_token: Drip Token
    :param amount: Amount of Drip Tokens
    """
    with DBSession() as session:
        try:
            # Create the SQLAlchemy update query
            update_query = (
                update(Ledger)
                .where(Ledger.drip_token == drip_token)
                .values(total_due=Ledger.total_due + amount)
            )
            
            # Execute the query
            result = session.execute(update_query)
            
            # Commit the transaction
            session.commit()
            
            return result.rowcount  # Returns the number of rows that were updated
        
        except Exception as e:
            logger.error(f"Error in ledger_add_unitdebt: {e}")
            session.rollback()
            raise e


def insert_payment(proposal_id=None, drip_token=None, amount=None, signature=None):
    """
    Insert or update a payment in the database using raw SQL executed with SQLAlchemy.
    """
    # Check for required parameters
    if proposal_id is None or drip_token is None or amount is None or signature is None:
        raise ValueError("Missing required fields")

    with DBSession() as session:
        try:
            upsert_query = text("""
                INSERT INTO payments (proposal_id, drip_token, amount, signature, created_at, updated_at)
                VALUES (:proposal_id, :drip_token, :amount, :signature, timezone('utc', NOW()), timezone('utc', NOW()))
                ON CONFLICT (proposal_id)
                DO UPDATE SET
                    drip_token = EXCLUDED.drip_token,
                    amount = EXCLUDED.amount,
                    signature = EXCLUDED.signature,
                    updated_at = timezone('utc', NOW())
            """)
            session.execute(upsert_query, {'proposal_id': proposal_id, 'drip_token': drip_token, 'amount': amount, 'signature': signature})

            # Commit the changes
            session.commit()
        
        except Exception as e:
            # In case of any exception, rollback the changes
            session.rollback()
            raise e


def get_owed_amount(drip_token=None, session_id=None):
    """
    Get the amount owed for a drip token
    :param session: Database session
    :param drip_token: Drip Token
    :return: Amount owed
    """
    if drip_token is None and session_id is None:
        raise ValueError("Must provide either drip_token or session_id")

    with DBSession() as session:
        try:
            result = session.execute(text("""
                SELECT 
                    agreements.domain,
                    agreements.proposal_id,
                    agreements.expires,
                    agreements.target_currency,
                    ledger.total_paid,
                    ledger.total_due,
                    sessions.payment_state
                FROM 
                    agreements
                JOIN 
                    ledger ON ledger.proposal_id = agreements.proposal_id
                JOIN
                    sessions ON sessions.drip_token = agreements.drip_token
                WHERE 
                    agreements.drip_token = :drip_token OR agreements.session_id = :session_id
            """) , {'drip_token': drip_token, 'session_id': session_id})
            
            return result.first()
        
        except NoResultFound:
            logger.warning(f"No session record found for drip_token: {drip_token}")
            raise Exception("No session record found")
        
        except Exception as e:
            logger.error(f"Error in get_owed_amount: {e}")
            raise e
    

def get_and_set_destroyed_agreements():
    """
    Get and set the destroyed agreements or 
    :param session: Database session
    :return: List of drip_tokens
    """
    drip_tokens = []
    with DBSession() as session:
        try:
            # Calculate the current epoch time plus 120
            claim_window_seconds = parser.getint('SchedulesAndSettings', 'claim_window_seconds', fallback=120)

            expired_time = int(time.time()) + claim_window_seconds
            query = text("""
                        WITH UpdatedAgreements AS (
                            UPDATE agreements
                            SET destroyed = true
                            WHERE expires <= :expired_time AND destroyed = false
                            RETURNING drip_token
                        ),
                        UpdatedSessions AS (
                            UPDATE sessions
                            SET destroyed = true
                            WHERE drip_token IN (SELECT drip_token FROM UpdatedAgreements)
                            RETURNING drip_token
                        ),
                        DestroyedSessions AS (
                            SELECT drip_token FROM sessions WHERE destroyed = true
                        )

                        SELECT drip_token FROM UpdatedAgreements
                        UNION
                        SELECT drip_token FROM UpdatedSessions
                        UNION
                        SELECT drip_token FROM DestroyedSessions
                        ORDER BY drip_token ASC;
                    """)

            # Execute the query and fetch the result
            result = session.execute(query, {'expired_time': expired_time})

            # Commit the changes
            session.commit()

            # Extract the drip_tokens from the result
            drip_tokens = [row[0] for row in result.fetchall()]

        except Exception as e:
            logger.error(f"Error in get_and_set_destroyed_agreements: {e}")
            session.rollback()
            raise e

        # Return the drip_tokens
        return drip_tokens


def flush_all_agreements():
    """
    flush all agreements, the server is going down, so we need to mark all agreements as destroyed
    we also need to claim all the payment channels we have open
    :param session: Database session
    :return: List of drip_tokens
    """
    drip_tokens = []
    with DBSession() as session:
        try:
            query = text("""
                        WITH UpdatedAgreements AS (
                            UPDATE agreements
                            SET destroyed = true
                            WHERE destroyed = false
                            RETURNING drip_token
                        ),
                        UpdatedSessions AS (
                            UPDATE sessions
                            SET destroyed = true
                            WHERE drip_token IN (SELECT drip_token FROM UpdatedAgreements)
                            RETURNING drip_token
                        ),
                        DestroyedSessions AS (
                            SELECT drip_token FROM sessions WHERE destroyed = true
                        )

                        SELECT drip_token FROM UpdatedAgreements
                        UNION
                        SELECT drip_token FROM UpdatedSessions
                        UNION
                        SELECT drip_token FROM DestroyedSessions
                        ORDER BY drip_token ASC;
                    """)

            # Execute the query and fetch the result
            result = session.execute(query)

            # Commit the changes
            session.commit()

            # Extract the drip_tokens from the result
            drip_tokens = [row[0] for row in result.fetchall()]

        except Exception as e:
            logger.error(f"Error in flush_all_agreements: {e}")
            session.rollback()
            raise e

        # Return the drip_tokens
        return drip_tokens


def get_channel_information(drip_token=None):
    if drip_token is None:
        raise ValueError("Must provide drip_token")
    
    with DBSession() as session:
        try:
            # Query using SQLAlchemy ORM
            results = session.query(
                Payment.amount,
                Payment.signature,
                Agreement.client_address,
                Agreement.client_public_key,
                Agreement.channel_id
            ).join(
                Agreement, Agreement.drip_token == Payment.drip_token
            ).filter(
                Payment.drip_token == drip_token
            ).first()

            return results
        
        except Exception as e:
            logger.error(f"Error in get_channel_information: {e}")
            raise e


def delete_agreement_record(drip_token=None):
    """
    Delete an agreement by drip_token
    :param session: Database session
    :param drip_token: Drip Token
    :return: Number of rows affected
    """
    if drip_token is None:
        raise ValueError("Must provide drip_token")
    
    with DBSession() as session:
        try:
            # Create the SQLAlchemy delete query
            delete_query = (
                delete(Agreement)
                .where(Agreement.drip_token == drip_token)
            )

            # Execute the query
            result = session.execute(delete_query)

            # Commit the transaction
            session.commit()

            return result.rowcount  # Returns the number of rows that were deleted
        
        except Exception as e:
            logger.error(f"Error in delete_agreement_record: {e}")
            session.rollback()
            raise e


def delete_session_record(drip_token=None):
    """
    Delete a session by drip_token
    :param session: Database session
    :param drip_token: Drip Token
    :return: Number of rows affected
    """
    if drip_token is None:
        raise ValueError("Must provide drip_token")

    with DBSession() as session:
        try:
            # Create the SQLAlchemy delete query
            delete_query = (
                delete(Session)
                .where(Session.drip_token == drip_token)
            )

            # Execute the query
            result = session.execute(delete_query)

            # Commit the transaction
            session.commit()

            return result.rowcount  # Returns the number of rows that were deleted
        
        except Exception as e:
            logger.error(f"Error in delete_session_record: {e}")
            session.rollback()
            raise e


def delete_ledger_record(drip_token=None):
    """
    Delete a ledger by drip_token
    :param session: Database session
    :param drip_token: Drip Token
    :return: Number of rows affected
    """
    if drip_token is None:
        raise ValueError("Must provide drip_token")

    with DBSession() as session:
        try:
            # Create the SQLAlchemy delete query
            delete_query = (
                delete(Ledger)
                .where(Ledger.drip_token == drip_token)
            )

            # Execute the query
            result = session.execute(delete_query)

            # Commit the transaction
            session.commit()

            return result.rowcount  # Returns the number of rows that were deleted

        except Exception as e:
            logger.error(f"Error in delete_ledger_record: {e}")
            session.rollback()
            raise e


def delete_payment_record(drip_token=None):
    """
    Delete a ledger by drip_token
    :param session: Database session
    :param drip_token: Drip Token
    :return: Number of rows affected
    """
    if drip_token is None:
        raise ValueError("Must provide drip_token")

    with DBSession() as session:
        try:
            # Create the SQLAlchemy delete query
            delete_query = (
                delete(Payment)
                .where(Payment.drip_token == drip_token)
            )

            # Execute the query
            result = session.execute(delete_query)

            # Commit the transaction
            session.commit()

            return result.rowcount  # Returns the number of rows that were deleted

        except Exception as e:
            logger.error(f"Error in delete_payment_record: {e}")
            session.rollback()
            raise e


def set_to_destroy(drip_token=None):
    """
    Set tables to destroy an active session.

    :param session: Database session
    :param drip_token: Unique drip token id from drip client
    """
    if not drip_token:
        raise Exception("Must provide drip_token")
    
    with DBSession() as session:
        try:
            # Set the session table to destroy the session
            query = session.query(Session)
            query = query.filter(Session.drip_token == drip_token)
            query.update({'destroyed': True})
            session.commit()

        except Exception as e:
            logger.error(f"Error in set_to_destroy, setting Session to destroy: {e}")

        try:
            # Set the agreement table to destroy the session
            query = session.query(Agreement)
            query = query.filter(Agreement.drip_token == drip_token)
            query.update({'destroyed': True})
            session.commit()    

        except Exception as e:
            logger.error(f"Error in set_to_destroy, setting Agreement to destroy: {e}")

        try:
            # Set the Leger table to destroy the session
            query = session.query(Ledger)
            query = query.filter(Ledger.drip_token == drip_token)
            query.update({'destroyed': True})
            session.commit()

        except Exception as e:
            logger.error(f"Error in set_to_destroy,  setting Ledger to destroy: {e}")


def past_due_kicker():
    """
    Destroy sessions, agreements, and ledger records that have a past_due_counter value over X setting, if set.
    """
    past_due_kicker_value = parser.getint('SchedulesAndSettings', 'past_due_kicker', fallback=0)
    if past_due_kicker_value == 0:
        return 0

    with DBSession() as session:
        try:
            # Update sessions
            query_sessions = text("""
                WITH PastDueLedgers AS (
                    SELECT drip_token
                    FROM ledger
                    WHERE past_due_counter >= :past_due_kicker
                )
                UPDATE sessions
                SET destroyed = TRUE
                WHERE drip_token IN (SELECT drip_token FROM PastDueLedgers);
            """)
            result = session.execute(query_sessions, {'past_due_kicker': past_due_kicker_value})
            session.commit()

            # Update agreements
            query_agreements = text("""
                WITH PastDueLedgers AS (
                    SELECT drip_token
                    FROM ledger
                    WHERE past_due_counter >= :past_due_kicker
                )
                UPDATE agreements
                SET destroyed = TRUE
                WHERE drip_token IN (SELECT drip_token FROM PastDueLedgers);
            """)
            session.execute(query_agreements, {'past_due_kicker': past_due_kicker_value})
            session.commit()

            # Update ledger
            query_ledger = text("""
                WITH PastDueLedgers AS (
                    SELECT drip_token
                    FROM ledger
                    WHERE past_due_counter >= :past_due_kicker and destroyed = false
                )
                UPDATE ledger
                SET destroyed = TRUE
                WHERE drip_token IN (SELECT drip_token FROM PastDueLedgers);
            """)
            session.execute(query_ledger, {'past_due_kicker': past_due_kicker_value})
            session.commit()

            return result.rowcount

        except Exception as e:
            logger.error(f"Error in past_due_kicker: {e}")
            session.rollback()
            raise e
