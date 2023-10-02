# XDripServer
Drip server for drip clients, supporting XRP ledger based payment channels


## Quick Start Guide / Early Release

What is the drip server?

The drip server helps services, providers, and developers integrate XRP ledger-based micro-payments via payment channels into their systems.  


## Requirements
- Python 3.10+
- Linux OS
- PostgreSQL 15 (Digital Ocean works well for demo)
- Access to the XRP Ledger or Xahau test network
* Take note, if using Xahau, the algo on the faucet differs for wallet generation from the XRP testnet faucet. 

## Installation

### Clone the repo: 
> `git clone git@github.com:calvincs/XDripServer.git`


### Configure config.ini

Any keys ending with _encrypted will become encrypted with the DRIP_SECRET env variable on start. 

The DRIP_SECRET env variable, for demo purposes, is set in the `run.sh` file.

```
[System]
domain = example.com
create_grpc_self_cert = true 
log_level = info
log_file_size_mb = 100
log_file_count = 10
log_to_console = true
max_grpc_workers = 10
grpc_port = 50051
```

If set to true, create_grpc_self_cert will generate its certificates.

```
[Database]
db_host = db-postgresql-somehost.somewhere.com
db_port = 25060
db_username_encrypted = demo_user
db_password_encrypted = demo_password
db_name = demo_db
db_pool_size = 15
db_ca_path = /etc/ssl/example-certificate.crt
debug=false
```

When debug is true, you will get verbose output from your SQL executions. While useful for troubleshooting, it can cause performance issues under load. 

```
[Wallet]
algorithm = ed25519
classic_address = rw64xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
secret_encrypted = sEDxxxxxxxxxxxxxxxxxxxxx
offload_classic_address = rw72xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
offload_over_threshold = 20000000
```
Which algorithm should you use when creating your wallet from the seed, see https://xrpl-py.readthedocs.io/en/latest/source/xrpl.html#xrpl.constants.CryptoAlgorithm

The offload address is where excess funds will be moved after our hot wallet accumulates excessive funds.
offload_over_threshold, in drops, tells the server when we need to move funds. 

If over this amount in drops, move whatever excess exists to the offload_over_threshold address.

```
[Terms]
payment_type = 0
inquiry_expiration = 60
payment_polling_interval = 60
min_channel_funding = 1000000
channel_expiration = 1800
destination_tag = 0
```
Terms define the conditions clients will use when connected to our server. The client must agree to these terms and set their payment channel correctly based on them.  

Payment type options:
```
0 - Both time-based and Unit based
1 - Time based
2 - Unit based
```


The logic used for Time-based payments
```DripEngine.py #L217
            # If the payment type is Both or TimeBased, we need to calculate the rate
            if tmp_data["PaymentType"] in ["TimeBased", "Both"]:
                # If XRP/XRP+ this in drops, where 1 is the smallest allowed value, always
                polling_interval = tmp_data["PollingInterval"]
                segments = int(channel_expiration / polling_interval)
                calculated_rate = int(math.ceil(min_channel_funding / segments))
                if calculated_rate == 0:
                    calculated_rate = 1
                tmp_data["Rate"] = calculated_rate
```
Inquiry expiration, time in seconds: the client has to set up a payment channel based on the information provided, and send a request to confirm the agreement with the server. 

Payment polling interval defines the time window a client must check for balance and pay any balance if it exists within—failure to do so increments a past_due counter. 

Min channel funding defines the minimum amount of drops the channel must be opened with. The logic will validate that it was this exact amount when the channel was opened. The client should not under or overfund the channel. 

Channel expiration defines the time in seconds the channel should be set to stay open for, awaiting a claim. This value aligns with the `SettleDelay` value used during the channel creation. 

Destination tag value ensures that incoming client creation contains a matching destination tag. 

This option may be removed or altered to enable dynamically setting this value. 


```
[Ledger]
ledger_url = https://s.altnet.rippletest.net:51234
```
Set the JSONRPC address of the network your server needs to connect to. 

```
[SchedulesAndSettings]
# 0 = off, 1+ = on, and how many
past_due_kicker = 10 
claim_window_seconds = 180
expired_window_seconds = 360
offload_interval_seconds = 900
```
If set past zero, past due kicker value will take any sessions that match or exceed that value and end the session for the client.

Claim window seconds: how many seconds from the time of close of the channel should we attempt to claim the payment channel. During this time, the client can no longer add any additional unit payments, and time-based rate increments have ended. The server will attempt to make the claim. Setting this number high enough to allow your server time to make the claim is essential. This number should be lower than your channel_expiration value in the Terms. 

Expired window seconds, the time in seconds till the payment channel closes, and the client should be allowed to refresh/fund the channel for additional time.

Offload interval seconds, how often the server should check the hot wallet balance of the server, and attempt to move funds if over the specified value to a cold wallet.

```
[gGRP_Certificate]
# Genreate a self-signed certificate for the gRPC server
# This is only used if create_grpc_self_cert is true, else use the paths below
generate_self_signed_cert = true
server_cert_name = server_cert.pem
server_key_name = server_key.pem

# Subject and Issuer Attributes
common_name = example.com
country_name = US
organization_name = Example Corp
email_address = admin@example.com

# Subject Alternative Names
san_dns_1 = localhost
san_dns_2 = 127.0.0.1

# Certificate Validity
validity_days = 365
```
Values used to generate a self-signed gRPC certificate.
If you need to use your own, point the config to those locations. Otherwise, set `generate_self_signed_cert = true`, and certs will be generated for you.

JWT private/public keys will be generated and added to your configuration file under the system section during startup. These can be replaced or updated, and the values will be re-encrypted on the next run.


We are now ready to run the server, let us use the helper script `run.sh` to kick off the server. Please review the contents of the run.sh file before using. You must `chmod +x run.sh` to allow it to execute.

If configuration items are missing or incorrect, you will receive an error during startup. 

CRTL+C will cause the server to shutdown in a systematic way. 


## Using the test_client.py

- Obtain a test network wallet: https://xrpl.org/xrp-testnet-faucet.html
- Use a text editor, add the wallet set to  #L26 of test_client.py
- Activate the virtual environment in drip-env.
    > `$>. drip-env/bin/activate`
- chmod test_client.py
    > `$>chmod +x test_client.py`
- Execute the test_client.py

You should now have a payment channel connected to your server, and the client should be making micropayments over time and unit-based. 

The top of the test_client has many options you can play with to get a feel of how things should work. Note that this client represents both a web server and the client and has slight error handling or flow control.

Better middleware should be written for web server integration and client communication with the web server. 




# Process Flow Overview:

**1. Session and DripToken Initialization:**
- On a client's first visit to the webpage, the server generates a `Session ID`.
- Simultaneously, the server requests the Drip Service to generate a `DripToken` for the client. This token is associated with the web browser's Session ID.

  [A] Server to Drip Service IPC call: `IPC://create_new_session?sessionid=1234567890`
  [B] Response from Drip Service includes details such as the DripToken, Domain, and a unique URI for the client.
  > "Action": "SessionCreated"
  
  > "Action": "CreateSession", "Message": error
  
  [C] Query by the webserver or application server
  > "Action": "QuerySession", "Message": "Session found"
  
  > "Action": "QuerySession", "Message": "Err: Session not found"
  
  > "Action": "QuerySession", "Message": "ERR: unknown error during session query"


**2. Client Interaction to Initiate Drip Service:**
- Clients interact with the "Start Drip Service" button on the website.
- Clicking this initiates a deep link, processed by the Drip Service client app on the user's device.


**3. Drip Client Inquiries:**
- The Drip Client sends an "Inquiry" to the web server's Drip service endpoint.
- This inquiry seeks details on the available options based on the DripToken.


**4. Drip Service Response:**
- The Drip Service sends back a "Proposal" which the Drip client can choose to accept or decline.
- This proposal contains important parameters such as ProposalID, PaymentType, PollingInterval, and others.
    > "Action" : "Proposal", "Proposal created successfully"
    
    > "Action" : "InquiryError", "Error creating inquiry payload: {e}" 
    
    > "Action" : "InquiryError", "Message": "ERR: General System Error"


**5. Client Agreement Process:**
- If the client accepts the proposal, they create a payment channel and send an "Agreement" payload to the Drip Service.
- Drip Service validates this agreement to ensure the payment channel's creation and proper funding.
    > "Action" : "AgreementAccepted", "Message": "Agreement accepted"
    
    > "Action" : "AgreementDenied", "Message": "ERR: Invalid payload"
    
    > "Action" : "AgreementDenied", "Message": "ERR: General System Error"


**6. Payment Polling Mechanism:**
- The Drip Client starts polling the Drip Service to inquire about the "AmountDue".
- This must be fulfilled within the designated "PollingInterval".


**7. Payment Execution:**
- The Drip Client sends the required payment to the Drip Service.
- The Drip Service validates this payment based on certain criteria and responds with either PaymentAccepted or PaymentDenied.
    [A] Client requests to know amount due within the polling interval.
    
    [B] Drip Service responds with the amount due.
    > "Action" : "AmountDue", "Message": None, Additional fields returned with the amount due, state, etc
    
    > "Action" : "AmountDue", "Message": "Err: Session not found"
    
    > "Action" : "AmountDue", "Message": "ERR: General System Error"

    [C] Client sends payment to Drip Service.
    > "Action" : "PaymentAccepted", "Message": "Payment accepted"
    
    > "Action" : "PaymentDenied", "Message": "ERR: Invalid signature"
    
    > "Action" : "PaymentDenied", "Message": "ERR: Invalid amount for payment"
    
    > "Action" : "PaymentDenied", "Message": "ERR: General System Error"


**8. Ongoing Payments:**
- The Drip Client and Drip Service continuously engage in steps 7-8 until nearing the Agreement's expiration.


**9. Agreement Refresh Options:**
- Clients can either let the agreement expire or request a "RefreshProposal" to extend the session.
- The Drip Service will respond with a "RefreshProposal" which the client can accept or decline.
    > "Action" : "RefreshProposal", "Message": "RefreshProposal created successfully"
    
    > "Action" : "RefreshProposalError", "Message": "ERR: General System Error"


**10. Refresh Agreement:**
- Clients can update the payment channel based on the Drip Server's "RefreshProposal".
    > "Action" : "RefreshApproved", "Message": "Refresh agreement accepted successfully"
    
    > "Action" : "RefreshDenied", "Message": "ERR: Invalid payload"
    
    > "Action" : "RefreshDenied", "Message": "ERR: General System Error"


**11. Direct Purchasing Mechanism:**
- The server can request a "MakeUnitPayment" directly from the Drip Server for added flexibility.
- This should be shielded from direct client access.
    > "Action" : "PurchaseApproved", "Message": "Purchase debt added to ledger successfully"
    
    > "Action" : "PurchaseDenied", "Message": "ERR: General System Error"
    
    > "Action" : "PurchaseDenied", "Message": "ERR: Debt exceeds channel balance"
    
    > "Action" : "PurchaseDenied", "Message": "ERR: Session is not configured for unit based debts"
    
    > "Action" : "PurchaseDenied", "Message": "ERR: Session is set to be removed"
    
    > "Action" : "PurchaseDenied", "Message": "ERR: Session awaiting payment, unable allow debt"
    
    > "Action" : "PurchaseDenied", "Message": "ERR: Session not found"


**12. Session Termination:**
- Sessions can be terminated either by the client's command or upon expiration.
- The Drip Server will then initiate the process of closing the payment channel.
    > "Action": "DestroySession", "Message": "Session destroyed"
    
    > "Action": "DestroySession", "Message": "Session not found"
    
    > "Action" : "DestroySession", "Message": "ERR: unknown error during session creation"



### Additional Points:
- Not all "Action" Responses are listed here, this is only a high lever overview of the process flow.

- Communication security and protocols:
  - Between Drip Server and Web Server: gRPC with TLS.
  - Drip Client to Drip Server: Via Web Server as a proxy.
  - Drip clients should always use a proxy to communicate with the Drip Server, to ensure rate limiting and other security measures are enforced.
  
- Ledger validations:
  - Channel Creation, Channel Refills, and Payments are always verified on the XRP Ledger.

- Off-ledger micropayments:
  - Sent from Drip client to Drip Server and are authenticated using PublicKey.

- Universal Applicability:
  - Although the example uses a web client, the process is compatible with any client communicating over HTTP. Similarly, while a Drip Client is mentioned, it could be any wallet interacting with the Drip Server using the specified protocol.

- While not required, its is recommended that the Drip Client create unique payment channels for each DripToken, and NOT use the clients main wallet seed in the Drip Client. This is to ensure that the Drip Client, if compromised, cannot be used to steal funds from the client's main wallet.  The risk is then limited to the funds in the Drip Client's payment channel.

## Process Flow Diagram
![Flow Diagram](https://github.com/calvincs/XDripServer/blob/main/flow.svg)
