import base64
from dnslib import RR, DNSRecord, RR, QTYPE, TXT, A
from typing import List
from cryptography.hazmat.primitives import hashes
import string
#from acme_client.__main__ import domains
 
Challenge = []


class DNS01Handler:
     
    def __init__(self, ip_addr: str):# DOMAIN_NAMES: domains):
        self.ip_addr = ip_addr
        #self.DOMAIN_NAMES = domains

        
    def resolve(self, request: DNSRecord, handler):
        
        incoming_query = request.get_q().get_qname()
        q_name = request.get_q().get_qname()
        #print("q_name", q_name)
        q_type = QTYPE[request.q.qtype]
        #print("q_type", q_type)
        #domain = str(q_name).split(".", 1)[1]
        #print("domain", domain)

        reply = request.reply()
        #print("incoming_query", incoming_query)

        if q_type == 'A' :
            # f = open("dnsResource.txt", "r")
        
            # content=f.read()
        
            reply.add_answer(RR(q_name, QTYPE.A, rdata=A(self.ip_addr)))


        if q_type == 'TXT' and str(q_name).startswith('_acme-challenge'):
            f = open("dnsResource.txt", "r")
            content=f.read()

            dig2= hashes.Hash(hashes.SHA256())
            dig2.update(content.encode())
            thumbprint_hashed = dig2.finalize()#base64.urlsafe_b64encode(thumbprint).rstrip(b'=').decode('utf-8')
            thumbprint_hashed = base64.urlsafe_b64encode(thumbprint_hashed).rstrip(b'=')

            #print("content", content)
        
            reply.add_answer(RR(q_name, QTYPE.TXT, rdata=TXT(thumbprint_hashed)))


        return reply
