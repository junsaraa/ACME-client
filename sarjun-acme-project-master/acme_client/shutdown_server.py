import hashlib
from http.server import BaseHTTPRequestHandler
import time
from urllib.parse import urlparse, parse_qs
import requests
import json
import base64 
import os

class SHUTDOWN_SERVER(BaseHTTPRequestHandler):


    
    def do_GET(self):
        print("you are in the shutdown server ####################")


        if self.path == "/shutdown":
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write("received shutdown down".encode("utf-8"))
            os._exit(1)

            # time.sleep(1)

            # self.server.shutdown()
        # else:
        #     self.send_response(404)
            

       
    
    # def do_HEAD(self):
    #     print("HEAD")
    #     self.send_response(200)
    #     self.send_header("Content-Type", "application/octet-stream")
    #     self.end_headers()
    
