from sqlalchemy import Column, String, DateTime, Integer, Boolean
from sqlalchemy import Enum
from sqlalchemy.ext.declarative import declarative_base
import datetime
from ulid import ULID

Base = declarative_base()

class Session(Base):
    """
    This is the session table. 
    It is used to store the session_id and drip_token.

    Fields:
        session_id is the session_id of the user's browser or application session.

        drip_token: a unique token that is used to identify the user's browser session.
        domain: the domain of the website that the user is visiting.
        uri: the URI of the website or application that generated the session.
        client_address: the wallet address.
        created_at: the date and time that the session was created.
        updated_at: the date and time that the session was last updated.
        destroyed: a boolean value that indicates if the session has been destroyed on the website or application.

        payment_state: the state of the payment for the session(s).
            - init: the session has been created, but we are waiting for an Agreement to be created.
            - paid: the session has been paid in full.
            - pending: the session is waiting for the next payment to be made.
            - overdue: the session is overdue for payment.
            - nsf: the session has insufficient funds to make a payment, the channel needs to be topped up.
            - error: there was an error processing the payment.
            - expired: the session has expired.
    """
    __tablename__ = 'sessions'
    session_id = Column(String(length=128), primary_key=True)
    drip_token = Column(String(length=26), index=True, unique=True, default=lambda: str(ULID()))
    domain = Column(String(length=128))
    uri = Column(String(length=1024))
    client_address = Column(String(length=36))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    payment_state = Column(Enum('init', 'paid', 'pending', 'overdue', 'nsf', 'error', 'expired', name='payment_state_enum'), default='init', index=True)
    destroyed = Column(Boolean, default=False)


class Agreement(Base):
    """
        This is the proposal table. 
        It is used to store the proposal_id and other information about the proposal.

        Fields:
         - proposal_id: a unique token that is used to identify the proposal for the Agreement.
         - session_id: a unique token that is used to identify the user's browser/app session.
         - drip_token: a unique token that is used to identify the user's Drip client session.
         - domain: the domain of the website/app that the user is visiting.
         - created_at: the date and time that the Agreement was created.
         - updated_at: the date and time that the Agreement was last updated.
         - expires: the date and time that the proposal expires.
         - payment_type: the type of payment that the proposal is for (Time, Unit Based or Both).
         - polling_interval: the interval in seconds that the client should poll the server for payment updates.
         - min_channel_funding: minimum amount of XRP Drops that the client can fund the channel with.
         - settlement_delay: delay in seconds that the client should wait before settling the channel.
         - target_currency: target currency that we are using to calculate the price of the proposal.
         - rate: the rate of the Agreement, if applicable, otherwise 0
         - client_address: XRP Classic address that the client used to fund the channel.
         - client_public_key: XRP Classic public key that the client used to make micropayments for the channel.
         - channel_id: payment channel id that the client setup to make micropayments.
         - destroyed: a boolean value that indicates if the Agreement has been destroyed.
    """
    __tablename__ = 'agreements'
    
    proposal_id = Column(String(length=26), primary_key=True, index=True, default=lambda: str(ULID()))
    session_id = Column(String(length=128), nullable=False, index=True)
    drip_token = Column(String(length=26), nullable=False, index=True)
    domain = Column(String(length=128), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    expires = Column(Integer, nullable=False)
    payment_type = Column(Enum('TimeBased', 'UnitBased', 'Both', name='payment_type_enum'), nullable=False)
    polling_interval = Column(Integer, nullable=False)
    min_channel_funding = Column(Integer, nullable=False)  # XRP Drops
    settlement_delay = Column(Integer, nullable=False)
    target_currency = Column(Enum('USD', 'EUR', 'XRP+', 'XRP', name='payment_currency_enum'), nullable=False)
    rate = Column(Integer, nullable=False, default=0)
    client_address = Column(String(length=36), nullable=False)  # XRP Classic Address
    client_public_key = Column(String(length=66), nullable=False)  # XRP Classic Public Key
    channel_id = Column(String(length=64), nullable=False, unique=True)  # XRP Classic Payment Channel ID
    destroyed = Column(Boolean, default=False)


class Ledger(Base):
    """
        This is the ledger table.
        It is used to track and store balance for the Agreement.

        If total_due == total_paid then the proposal is paid in full at the time of the query.
        If total_due > total_paid, and the last_payment_time >= polling interval, then the Agreement is overdue state.
        If total_due > total_paid, and the last_payment_time <= polling interval, then the Agreement is pending state.
        If channel_balance <= total_due, then the Agreement is in nsf state, and the channel needs additional funding.

        Fields:
        - proposal_id: unique token that is used to identify the proposal for the Agreement.
        - drip_token: unique token that is used to identify the user's Drip client session.
        - total_due: total amount due for the Agreement.
        - total_paid: total amount paid for the Agreement.
        - last_payment_timestamp: date and time that the last payment was received.
        - created_at: date and time that the Agreement was created.
        - updated_at: date and time that the Agreement was last updated.
        - channel_balance: current balance of the payment channel.
        - past_due_counter: how many times has the Agreement been past due, missed a payment.
        - refresh_counter: how many times has the Agreement been refreshed.
        - rate: the rate of the Agreement.
        - payment_type: the type of payment that the proposal is for (Time, Unit Based or Both).
        - destroyed: a boolean value that indicates if the Agreement has been destroyed.

    """
    __tablename__ = 'ledger'
    
    proposal_id = Column(String(length=26), nullable=False, index=True)
    drip_token = Column(String(length=26), primary_key=True, nullable=False, index=True)
    total_due = Column(Integer, default="0", nullable=False)  # Total amount due at this time
    total_paid = Column(Integer, default="0", nullable=False)  # Total amount paid at this time
    last_payment_timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)  # Time last payment was received
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    channel_balance = Column(Integer, nullable=False)
    past_due_counter = Column(Integer, nullable=False, default=0)  # Number of times the Agreement has been past due
    refresh_counter = Column(Integer, nullable=False, default=0)  # Number of times the Agreement has been refreshed
    rate = Column(Integer, nullable=False, default=0)
    payment_type = Column(Enum('TimeBased', 'UnitBased', 'Both', name='payment_type_enum'), nullable=False)
    destroyed = Column(Boolean, default=False)


class Payment(Base):
    """
    This is the Payment table.
    It is used to track payments from the client, 
     - including timestamp, proposal_id, drip_token, amount, signature, and signature validation.

    Fields:
        proposal_id: the ID of the proposal associated with the payment.
        drip_token: the token used to identify the user's browser session.
        amount: the amount of the payment.
        signature: the signature associated with the payment.
        created_at: the time when the payment entry was created.
        updated_at: the time when the payment entry was last updated.
    """
    __tablename__ = 'payments'
    
    proposal_id = Column(String(length=26), nullable=False, index=True)
    drip_token = Column(String(length=26), primary_key=True, nullable=False, index=True)
    amount = Column(Integer, nullable=False)
    signature = Column(String(length=256), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

