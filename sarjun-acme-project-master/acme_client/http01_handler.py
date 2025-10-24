import hashlib
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import requests
import json
import base64 

class HTTP01Handler(BaseHTTPRequestHandler):


    
    def do_GET(self):
        f = open("httpResource.txt", "r")
        global output
        output = f.read()

        parsed_url = urlparse(self.path)
        #print("parsed_url", parsed_url)
        query_params = parse_qs(parsed_url.query)

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        self.wfile.write(output.encode("utf-8"))
    
    def do_HEAD(self):
        print("HEAD")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
    
