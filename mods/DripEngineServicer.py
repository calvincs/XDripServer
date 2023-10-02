import grpc_drip_server_pb2 as drip_pb2
import grpc_drip_server_pb2_grpc as drip_grpc

class DripEngineServicer(drip_grpc.DripEngineServiceServicer):

    def __init__(self, engine):
        self.engine = engine


    def CreateSession(self, request, context):
        rspo = self.engine.CreateSession(session_id=request.session_id)
        return drip_pb2.CreateSessionResponse(
            Action=rspo.get("Action", "CreateSession"),
            SessionID=rspo.get("SessionID", ""),
            DripToken=rspo.get("DripToken", ""),
            Domain=rspo.get("Domain", ""),
            URI=rspo.get("URI", ""),
        )


    def GetSession(self, request, context):
        rspo = self.engine.GetSession(session_id=request.session_id, drip_token=request.drip_token)
        return drip_pb2.GetSessionResponse(
            Action=rspo.get("Action", "QuerySession"),
            SessionID=rspo.get("SessionID", ""),
            DripToken=rspo.get("DripToken", ""),
            Domain=rspo.get("Domain", ""),
            URI=rspo.get("URI", ""),
            PaymentState=rspo.get("PaymentState", ""),
            ClientAddress=rspo.get("ClientAddress", ""),
            Message=rspo.get("Message", ""),
        )


    def ClientInquiry(self, request, context):
        rspo = self.engine.ClientInquiry(drip_token=request.drip_token)
        return drip_pb2.ClientInquiryResponse(
            Action=rspo.get("Action", "Proposal"),
            JWT=rspo.get("JWT", ""),
            Message=rspo.get("Message", ""),
        )


    def ClientAcceptAgreement(self, request, context):
        payload = {
            "Action": request.Action,
            "TXHash": request.TXHash,
            "JWTPayload": request.JWTPayload
        }
        rspo = self.engine.ClientAcceptAgrement(payload=payload)
        return drip_pb2.ClientAcceptAgreementResponse(
            Action=rspo.get("Action", "Agreement"),
            DripToken=rspo.get("DripToken", ""),
            ProposalID=rspo.get("ProposalID", ""),
            ChannelID=rspo.get("ChannelID", ""),
            Expires=rspo.get("Expires", ""),
            Message=rspo.get("Message", ""),
        )


    def ClientRefreshInquiry(self, request, context):
        rspo = self.engine.ClientRefreshInquiry(drip_token=request.drip_token)
        return drip_pb2.ClientInquiryResponse(
            Action=rspo.get("Action", "Proposal"),
            JWT=rspo.get("JWT", ""),
            Message=rspo.get("Message", ""),
        )


    def ClientRefreshAccept(self, request, context):
        payload = {
            "Action": request.Action,
            "TXHash": request.TXHash,
            "JWTPayload": request.JWTPayload
        }
        rspo = self.engine.ClientRefreshAccept(payload=payload)
        return drip_pb2.ClientRefreshAcceptResponse(
            Action=rspo.get("Action", ""),
            Message=rspo.get("Message", ""),
        )


    def MakeUnitPayment(self, request, context):
        rspo = self.engine.MakeUnitPayment(session_id=request.session_id, drip_token=request.drip_token, amount=request.amount)
        return drip_pb2.MakeUnitPaymentResponse(
            Action=rspo.get("Action", ""),
            Message=rspo.get("Message", ""),
        )


    def GetOwedInfo(self, request, context):
        rspo = self.engine.GetOwedInfo(drip_token=request.drip_token, session_id=request.session_id)
        return drip_pb2.GetOwedInfoResponse(
            Action=rspo.get("Action", "AmountDue"),
            Domain=rspo.get("Domain", ""),
            ProposalID=rspo.get("ProposalID", ""),
            TTL=rspo.get("TTL", 0),
            Currency=rspo.get("Currency", ""),
            AmountPaid=rspo.get("AmountPaid", 0),
            AmountDue=rspo.get("AmountDue", 0),
            State=rspo.get("State", ""),
            Message=rspo.get("Message", ""),
        )
    

    def ProcessPayment(self, request, context):
        rspo = self.engine.ProcessPayment(drip_token=request.drip_token, amount=request.amount, signature=request.signature)
        return drip_pb2.ProcessPaymentResponse(
            Action=rspo.get("Action", "Payment"),
            Message=rspo.get("Message", ""),
        )


    def DestroySession(self, request, context):
        rspo = self.engine.DestroySession(session_id=request.session_id, drip_token=request.drip_token)
        return drip_pb2.DestroySessionResponse(
            Action=rspo.get("Action", "DestroySession"),
            Message=rspo.get("Message", ""),
        )
