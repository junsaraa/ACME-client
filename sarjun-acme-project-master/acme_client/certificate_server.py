import hashlib
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import requests
import os
import ssl
import base64 

class CERTIFICATE_HTTP_server(BaseHTTPRequestHandler):

#open ssl with private key, then write certificate to the response
    def do_GET(self):
        f = open("downloadedCertificate.pem", "r")
        #global certificate
        certificate = f.read()

        print("in the cert server")

        self.send_response(200)
        #self.send_header(200, "application/pem-certificate-chain", len(certificate.encode('utf-8'))) #-pem
        self.end_headers()
        self.wfile.write(certificate.encode("utf-8"))
    
    def do_HEAD(self):
        print("HEAD")
        self.send_response(200)
        #self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()

