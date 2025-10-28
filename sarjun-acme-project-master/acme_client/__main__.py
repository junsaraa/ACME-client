from http.server import HTTPServer
from threading import Thread
import time
from dnslib.server import DNSServer
import hashlib
import argparse

from acme_client.http01_handler import HTTP01Handler
from acme_client.dns01_handler import DNS01Handler
from acme_client.certificate_server import CERTIFICATE_HTTP_server
from acme_client.shutdown_server import SHUTDOWN_SERVER


import requests
import json
import base64 
import os
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding

from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Name, NameAttribute, SubjectAlternativeName
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes as crypt_hashes
from cryptography.x509 import CertificateSigningRequestBuilder
from cryptography.x509 import DNSName
from cryptography import x509



from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from requests.structures import CaseInsensitiveDict


nonce_retrieved = {}
PEBBLE_CERTIFICATE_PATH = 'project/pebble.minica.pem'

def generate_priv_pub_key():

    priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend()) #default_backend???

    pub_key = priv_key.public_key()

    return priv_key, pub_key

def x_y_publicNum(key_pub):
    num = key_pub.public_numbers()
    x = num.x.to_bytes(32, byteorder='big')
    y = num.y.to_bytes(32, byteorder='big')

    return x,y

def jws_generation(private_key, signing_input):
    signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    sig_encoded  = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')

    r,s = decode_dss_signature(signature)
    r_byte = r.to_bytes(32, byteorder='big')
    s_byte = s.to_bytes(32, byteorder='big')
 
    JWS_Signature = r_byte+s_byte
    JWS_Signature_tob64 = base64.urlsafe_b64encode(JWS_Signature).rstrip(b'=').decode('utf-8')

    return JWS_Signature_tob64

    
def jsonify(input):
    res = CaseInsensitiveDict(input)
    if isinstance(res, CaseInsensitiveDict):
        res = dict(res)
    
    return json.dumps(res)


def nonce_creator(length=32):
    nonce_bytes = os.urandom(length)

    return nonce_bytes


def urlsafe_base64_encoding(input):
    jsonBytes = json.dumps(input).replace(" ", "").encode('utf-8')
    urlsafe_input = base64.urlsafe_b64encode(jsonBytes).rstrip(b'=')
    return urlsafe_input.decode('utf-8')


def acme_get_directory(directory):

    response = requests.get(directory, verify= PEBBLE_CERTIFICATE_PATH)
    response.raise_for_status()
    print(f"dir Status Code: {response.status_code}")
    print(f"dir Response Body: {response.text}")
    return response.json()


def acme_get_newNonce(directory_res):
    directory_getJson = jsonify(directory_res)
    newNonce_url = json.loads(directory_getJson).get('newNonce') 
    nonce_request = requests.head(newNonce_url, verify= PEBBLE_CERTIFICATE_PATH)
    print(f"newNonce Status Code: {nonce_request.status_code}")
    print(f"newNonce Response Body: {nonce_request.headers}")

    return nonce_request.headers


def acme_create_account(newNonce, directory_res ):
    directory_getJson = jsonify(directory_res)
    newAccount_url = json.loads(directory_getJson).get('newAccount') 
    print("newAccount_url", newAccount_url)
    newNonceJson = jsonify(newNonce)
    nonce = json.loads(newNonceJson).get('Replay-Nonce')
    print("nonce", nonce)

    #generation of key pair
    key_priv, key_pub = generate_priv_pub_key()
    x,y = x_y_publicNum(key_pub)


    protected={"alg":"ES256",
               "jwk":{"kty":"EC","crv":"P-256","x":base64.urlsafe_b64encode(x).decode('utf-8').rstrip("="),"y":base64.urlsafe_b64encode(y).decode('utf-8').rstrip("=")},
               "nonce":nonce,
               "url":newAccount_url}
    payload ={"termsOfServiceAgreed":True}


    encoded_header = urlsafe_base64_encoding(protected)
    encoded_payload = urlsafe_base64_encoding(payload)



    sig_in = f"{encoded_header}.{encoded_payload}".encode('utf-8')



    JWS_Signature_tob64 = jws_generation(key_priv, sig_in)
 
    headers = {"Content-type":"application/jose+json"}


    jws_final = json.dumps({"protected":encoded_header,"payload":encoded_payload,"signature":JWS_Signature_tob64})
    jws_final = jws_final.replace(" ", "") 

    
    createAccount_request = requests.post(newAccount_url, headers = headers, data=jws_final, verify=PEBBLE_CERTIFICATE_PATH)

    print(f"newAccount Status Code: {createAccount_request.status_code}")
    print(f"newAccount Response Body: {createAccount_request.headers}")
    return createAccount_request.json(), createAccount_request.headers, key_priv, key_pub


def acme_post_order(directory, accountResponse, newAccHeaders,  key_priv, key_pub, domains):

    nonceAccount = jsonify(newAccHeaders)
    previousNonce = json.loads(nonceAccount).get('Replay-Nonce') 
    resourceUrl = json.loads(nonceAccount).get('Location')
   
    newAccountJson = jsonify(directory)
    newOrder_url = json.loads(newAccountJson).get('newOrder') 


    headers = {"Content-type":"application/jose+json"}

    protected={"alg":"ES256",
               "kid":resourceUrl,
               "nonce":previousNonce,
               "url":newOrder_url}
    payload ={"identifiers": []}


    for i in domains:
        print(i)
        payload.get("identifiers").append({ "type": "dns", "value": i })
    print("payload multi domain", payload)

    

    encoded_header = urlsafe_base64_encoding(protected)
    encoded_payload = urlsafe_base64_encoding(payload)
    sig_in = f"{encoded_header}.{encoded_payload}".encode('utf-8')

    JWS_Signature_tob64 = jws_generation(key_priv, sig_in)

    jws_final = json.dumps({"protected":encoded_header,"payload":encoded_payload,"signature":JWS_Signature_tob64})
    jws_final = jws_final.replace(" ", "") 



    newOrder_request = requests.post(newOrder_url, headers = headers, data=jws_final, verify=PEBBLE_CERTIFICATE_PATH)

    print(f"newOrder Status Code: {newOrder_request.status_code}")
    print(f"newOrder Response Body: {newOrder_request.headers}")

    return newOrder_request.json(), newOrder_request.headers

def polling_multi(orderResponse, newAccHeaders, newOrderHeaders, key_priv, domains):

    authorizationURL = json.loads(jsonify(orderResponse)).get('authorizations')

    print("polling auth url", authorizationURL)

    validated_domains = []
    global new_header

    print("polling arg domains", domains)



    for i, domain in enumerate(domains):
        print("for loop i and domain", i, domain)
        if i==0:

            
            authz_body, authz_header, my_auth = acme_authorization_order(orderResponse, newAccHeaders, newOrderHeaders, key_priv, authorizationURL[i])
            challenging_text, challenging_header  = challenge_relay(chall_type, newOrder, authz_body, authz_header, newAccHeaders, priv, pub, my_auth)
            new_header = challenging_header
            print("challenging_text", challenging_text)
            print("challenging_header", challenging_header)
            identifier = challenging_text.get('identifier')

            validated_domains.append(identifier.get('value'))
    
        else:
            authz_body, authz_header, my_auth = acme_authorization_order(orderResponse, newAccHeaders, new_header, key_priv, authorizationURL[i])
            challenging_text, challenging_header  = challenge_relay(chall_type, newOrder, authz_body, authz_header, newAccHeaders, priv, pub, my_auth)
            new_header = challenging_header

            identifier = challenging_text.get('identifier')

            if domain.startswith('*.'): 
                validated_domains.append(domain)
            else:
                validated_domains.append(identifier.get('value'))

    return challenging_text, challenging_header, validated_domains



def acme_authorization_order(orderResponse, newAccHeaders, newOrderHeaders, key_priv, authorizationURL):

    previousNonce = json.loads(jsonify(newOrderHeaders)).get('Replay-Nonce') 
    locationKid = json.loads(jsonify(newAccHeaders)).get('Location')
    
    my_auth = authorizationURL

    headers = {"Content-type":"application/jose+json"}

    protected={"alg":"ES256",
               "kid":locationKid,
               "nonce":previousNonce,
               "url":my_auth}
    
    payload = ""
    encoded_header = urlsafe_base64_encoding(protected)

    sig_in = f"{encoded_header}.{payload}".encode('utf-8')
    JWS_Signature_tob64 = jws_generation(key_priv, sig_in)

    jws_final = json.dumps({"protected":encoded_header,"payload":payload,"signature":JWS_Signature_tob64})
    jws_final = jws_final.replace(" ", "") 



    newAuthz_request = requests.post(url=my_auth, headers = headers, data=jws_final, verify=PEBBLE_CERTIFICATE_PATH)

    print(f"newAuthz Status Code: {newAuthz_request.status_code}")
    print(f"newAuthz Response Header: {newAuthz_request.headers}")
    print(f"newAuthz Response Text: {newAuthz_request.text}")

    return newAuthz_request.json(), newAuthz_request.headers, my_auth


def http01_challenge(newOrder, newAuthz, newAuthzHeaders, newAccHeaders, key_priv, key_pub, authorizationURL):
        
        
        x,y = x_y_publicNum(key_pub)

        jwk={"crv":"P-256","kty":"EC","x":base64.urlsafe_b64encode(x).decode('utf-8').rstrip("="),"y":base64.urlsafe_b64encode(y).decode('utf-8').rstrip("=")}

        thumbprint = json.dumps(jwk, separators=(',', ':'), sort_keys=True).encode()
        digest= hashes.Hash(hashes.SHA256())
        digest.update(thumbprint)
        thumbprint = digest.finalize()
        thumbprint = base64.urlsafe_b64encode(thumbprint).rstrip(b'=').decode('utf-8')


        newAuthzJson = json.loads(jsonify(newAuthz))

        findHttp01Challenge = next((challenge for challenge in newAuthzJson['challenges'] if challenge['type'] == 'http-01'), None)
        http01token = findHttp01Challenge.get('token')
        challengeURL = findHttp01Challenge.get('url')

        keyAuthorization = f"{http01token}.{thumbprint}"

        resource = keyAuthorization.encode('utf-8').decode()

        f = open("httpResource.txt", "w")
        f.write(resource)
        f.close()

        headers = {"Content-type":"application/jose+json"}

        locationKid = json.loads(jsonify(newAccHeaders)).get('Location')
        previousNonce = json.loads(jsonify(newAuthzHeaders)).get('Replay-Nonce') 
        

        #JWS Generation
        protected={"alg":"ES256","kid":locationKid,"nonce":previousNonce,"url":challengeURL}
    
        payload ={}

        encoded_header = urlsafe_base64_encoding(protected)
        encoded_payload = urlsafe_base64_encoding(payload)


        sig_in = f"{encoded_header}.{encoded_payload}".encode('utf-8')
        JWS_Signature_tob64 = jws_generation(key_priv, sig_in)
        jws_final = json.dumps({"protected":encoded_header,"payload":encoded_payload,"signature":JWS_Signature_tob64})
        jws_final = jws_final.replace(" ", "") 

        


        handler_post = requests.post(challengeURL, headers = headers, data=jws_final, verify=PEBBLE_CERTIFICATE_PATH)

        newNonce = json.loads(jsonify(handler_post.headers)).get('Replay-Nonce') 

        if handler_post:
            
            headers = {"Content-type":"application/jose+json"}

            protected={"alg":"ES256",
                    "kid":locationKid,
                    "nonce":newNonce,
                    "url":authorizationURL}
            
            payload = ""
            encoded_header = urlsafe_base64_encoding(protected)
            encoded_payload = urlsafe_base64_encoding(payload)

            sig_in = f"{encoded_header}.{payload}".encode('utf-8')
            JWS_Signature_tob64 = jws_generation(key_priv, sig_in)

            jws_final = json.dumps({"protected":encoded_header,"payload":payload,"signature":JWS_Signature_tob64})
            jws_final = jws_final.replace(" ", "") 


            http01Validation_request = requests.post(url=authorizationURL, headers = headers, data=jws_final, verify=PEBBLE_CERTIFICATE_PATH)

            
            
            while_timeout = time.time() +10
            while http01Validation_request.json().get('status') is not "valid" and time.time() < while_timeout:

                newNonce2  = json.loads(jsonify(http01Validation_request.headers)).get('Replay-Nonce')

                headers = {"Content-type":"application/jose+json"}
                protected={"alg":"ES256",
                        "kid":locationKid,
                        "nonce":newNonce2,
                        "url":authorizationURL}
                
                payload = ""
                encoded_header = urlsafe_base64_encoding(protected)

                sig_in = f"{encoded_header}.{payload}".encode('utf-8')
                JWS_Signature_tob64 = jws_generation(key_priv, sig_in)

                jws_final = json.dumps({"protected":encoded_header,"payload":payload,"signature":JWS_Signature_tob64})
                jws_final = jws_final.replace(" ", "")
                http01Validation_request = requests.post(url=authorizationURL, headers = headers, data=jws_final, verify=PEBBLE_CERTIFICATE_PATH)
                 

            print(f"http01Validation_request Status Code: {http01Validation_request.status_code}")
            print(f"http01Validation_request Response Body: {http01Validation_request.headers}")
            print(f"http01Validation_request json Response : {http01Validation_request.text}")

            return http01Validation_request.json(), http01Validation_request.headers
        
        else:
            return "no response"
    

def dns01_challenge(newOrder, newAuthz, newAuthzHeaders, newAccHeaders, key_priv, key_pub, authorizationURL):
        
        
        x,y = x_y_publicNum(key_pub)

        authorization = json.loads(jsonify(newOrder)).get('authorizations')
    
        my_auth = authorizationURL
        print("DEBUG auth url passed to the ard", my_auth)

        print("DEBUG new Authz : ", newAuthz )
    



        ########Thumbprint generation##########
        jwk={"crv":"P-256","kty":"EC","x":base64.urlsafe_b64encode(x).decode('utf-8').rstrip("="),"y":base64.urlsafe_b64encode(y).decode('utf-8').rstrip("=")}

        thumbprint = json.dumps(jwk, separators=(',', ':'), sort_keys=True).encode()
        digest= hashes.Hash(hashes.SHA256())
        digest.update(thumbprint)
        thumbprint = digest.finalize()
        thumbprint = base64.urlsafe_b64encode(thumbprint).decode('utf-8').rstrip("=")

        newAuthzJson = json.loads(jsonify(newAuthz))
        findDNS01Challenge = next((challenge for challenge in newAuthzJson['challenges'] if challenge['type'] == 'dns-01'), None)
        dns01token = findDNS01Challenge.get('token')
        challengeURL = findDNS01Challenge.get('url')

        
        temp_keyAuthorization = f"{dns01token}.{thumbprint}"
        resource = temp_keyAuthorization.encode('utf-8').decode()

        f = open("dnsResource.txt", "w")
        f.write(resource)
        f.close()



        headers = {"Content-type":"application/jose+json"}

        locationKid = json.loads(jsonify(newAccHeaders)).get('Location')
        previousNonce = json.loads(jsonify(newAuthzHeaders)).get('Replay-Nonce') 

        protected={"alg":"ES256","kid":locationKid,"nonce":previousNonce,"url":challengeURL}
        payload ={}

        encoded_header = urlsafe_base64_encoding(protected)
        encoded_payload = urlsafe_base64_encoding(payload)

        sig_in = f"{encoded_header}.{encoded_payload}".encode('utf-8')
        JWS_Signature_tob64 = jws_generation(key_priv, sig_in)
        jws_final = json.dumps({"protected":encoded_header,"payload":encoded_payload,"signature":JWS_Signature_tob64})
        jws_final = jws_final.replace(" ", "") 


        urlHandler = requests.post(url=challengeURL, headers = headers, data=jws_final, verify=PEBBLE_CERTIFICATE_PATH)
        print("handler_get_headers", urlHandler.headers)
        print("handler_get", urlHandler.text)
        print("handler_post", urlHandler)

        newNonce = json.loads(jsonify(urlHandler.headers)).get('Replay-Nonce') 

        if urlHandler:
            
            headers = {"Content-type":"application/jose+json"}

            protected={"alg":"ES256",
                    "kid":locationKid,
                    "nonce":newNonce,
                    "url":my_auth}
            
            payload = ""
            encoded_header = urlsafe_base64_encoding(protected)
            encoded_payload = urlsafe_base64_encoding(payload)

            sig_in = f"{encoded_header}.{payload}".encode('utf-8')
            JWS_Signature_tob64 = jws_generation(key_priv, sig_in)

            jws_final = json.dumps({"protected":encoded_header,"payload":payload,"signature":JWS_Signature_tob64})
            jws_final = jws_final.replace(" ", "") 


            dns01Validation_request = requests.post(url=my_auth, headers = headers, data=jws_final, verify=PEBBLE_CERTIFICATE_PATH)

            
            
            while_timeout = time.time() +10
            while dns01Validation_request.json().get('status') is not "ready" and time.time() < while_timeout:

                newNonce  = json.loads(jsonify(dns01Validation_request.headers)).get('Replay-Nonce')

                headers = {"Content-type":"application/jose+json"}
                protected={"alg":"ES256",
                        "kid":locationKid,
                        "nonce":newNonce,
                        "url":my_auth}
                
                payload = ""
                encoded_header = urlsafe_base64_encoding(protected)

                sig_in = f"{encoded_header}.{payload}".encode('utf-8')
                JWS_Signature_tob64 = jws_generation(key_priv, sig_in)

                jws_final = json.dumps({"protected":encoded_header,"payload":payload,"signature":JWS_Signature_tob64})
                jws_final = jws_final.replace(" ", "")
                dns01Validation_request = requests.post(url=my_auth, headers = headers, data=jws_final, verify=PEBBLE_CERTIFICATE_PATH)


            

            print(f"dns01Validation_request Status Code: {dns01Validation_request.status_code}")
            print(f"dns01Validation_request Response headers: {dns01Validation_request.headers}")
            print(f"dns01Validation_request json Response : {dns01Validation_request.text}")

            return dns01Validation_request.json(), dns01Validation_request.headers
        
        else:
            return "no response"

def challenge_relay(challenge_type, newOrder, newAuthz, newAuthzHeaders, newAccHeaders, priv, pub, authorizationURL):
    if challenge_type == 'dns01':
        dnsChalz, dnsChalzHeader = dns01_challenge(newOrder, newAuthz, newAuthzHeaders, newAccHeaders, priv, pub, authorizationURL)
        return dnsChalz, dnsChalzHeader
    elif challenge_type == 'http01':
        http01_chalz, http01Header = http01_challenge(newOrder, newAuthz,newAuthzHeaders, newAccHeaders, priv, pub, authorizationURL) 
        return http01_chalz, http01Header
    else :
        error = print("wrong challenge type")
        return error


def csr(newOrder, newOrderHeader, http01Header, newAccHeaders,  key_priv, validated_domains):

    new_private_key = ec.generate_private_key(ec.SECP256R1())
    #public_key = new_private_key.public_key()

    csrURL = json.loads(jsonify(newOrder)).get('finalize')
    certificateURL = json.loads(jsonify(newOrderHeader)).get('Location')
    locationKid = json.loads(jsonify(newAccHeaders)).get('Location')
    previousNonce = json.loads(jsonify(http01Header)).get('Replay-Nonce') 

    headers = {"Content-type":"application/jose+json"}

    alternatives = x509.SubjectAlternativeName([x509.DNSName(name) for name in validated_domains]) #list of validated names
    
    #certificateRequestInfo
    subj = x509.Name([NameAttribute(NameOID.COMMON_NAME, validated_domains[0][0])])
    csr_input = x509.CertificateSigningRequestBuilder().subject_name(subj)

    csr_input = csr_input.add_extension(alternatives, critical=False)

    csr_signed = csr_input.sign(new_private_key, hashes.SHA256())

    der = csr_signed.public_bytes(serialization.Encoding.DER)
    csr_encoded = base64.urlsafe_b64encode(der).rstrip(b'=').decode('utf-8')


    protected={"alg":"ES256","kid":locationKid,"nonce":previousNonce,"url":csrURL}
    payload ={"csr":csr_encoded}

    encoded_header = urlsafe_base64_encoding(protected)
    encoded_payload = urlsafe_base64_encoding(payload)

    sig_in = f"{encoded_header}.{encoded_payload}".encode('utf-8')
    JWS_Signature_tob64 = jws_generation(key_priv, sig_in)
    jws_final = json.dumps({"protected":encoded_header,"payload":encoded_payload,"signature":JWS_Signature_tob64})
    jws_final = jws_final.replace(" ", "") 


    csrRequest = requests.post(url=csrURL, headers = headers, data=jws_final, verify=PEBBLE_CERTIFICATE_PATH)

    if csrRequest:
        newNonce  = json.loads(jsonify(csrRequest.headers)).get('Replay-Nonce')
            
        headers = {"Content-type":"application/jose+json"}
        protected={"alg":"ES256","kid":locationKid,"nonce":newNonce,"url":certificateURL}
        payload =""
        encoded_header = urlsafe_base64_encoding(protected)
        encoded_payload = urlsafe_base64_encoding(payload)

        sig_in = f"{encoded_header}.{payload}".encode('utf-8')
        JWS_Signature_tob64 = jws_generation(key_priv, sig_in)

        jws_final = json.dumps({"protected":encoded_header,"payload":payload,"signature":JWS_Signature_tob64})
        jws_final = jws_final.replace(" ", "") 


        csr_request = requests.post(url=certificateURL, headers = headers, data=jws_final, verify=PEBBLE_CERTIFICATE_PATH)

            
            
        while_timeout = time.time() + 30
        while csr_request.json().get('status') is not "valid" and time.time() < while_timeout:

            newNonce  = json.loads(jsonify(csr_request.headers)).get('Replay-Nonce')

            headers = {"Content-type":"application/jose+json"}
            protected={"alg":"ES256",
                        "kid":locationKid,
                        "nonce":newNonce,
                        "url":certificateURL}
                
            payload =""
            encoded_header = urlsafe_base64_encoding(protected)
            encoded_payload = urlsafe_base64_encoding(payload)

            sig_in = f"{encoded_header}.{payload}".encode('utf-8')
            JWS_Signature_tob64 = jws_generation(key_priv, sig_in)

            jws_final = json.dumps({"protected":encoded_header,"payload":payload,"signature":JWS_Signature_tob64})
            jws_final = jws_final.replace(" ", "")
            csr_request = requests.post(url=certificateURL, headers = headers, data=jws_final, verify=PEBBLE_CERTIFICATE_PATH)
            
            

        print(f"csr_request Status Code: {csr_request.status_code}")
        print(f"csr_request Response Body: {csr_request.headers}")
        print(f"csr_request json Response : {csr_request.text}")

        return csr_request.json(), csr_request.headers, new_private_key
        
    else:
        return "no response"
        

def downloadCertificate(newOrder, csrResponse, csrHeader, newAccHeaders,  key_priv, domains):
    
    downloadURL = json.loads(jsonify(csrResponse)).get('certificate') #which account
    locationKid = json.loads(jsonify(newAccHeaders)).get('Location')
    previousNonce = json.loads(jsonify(csrHeader)).get('Replay-Nonce') 
   

    headers = {"Content-type":"application/jose+json"}

    protected={"alg":"ES256","kid":locationKid,"nonce":previousNonce,"url":downloadURL}
    payload =""

    encoded_header = urlsafe_base64_encoding(protected)
    

    sig_in = f"{encoded_header}.{payload}".encode('utf-8')
    JWS_Signature_tob64 = jws_generation(key_priv, sig_in)
    jws_final = json.dumps({"protected":encoded_header,"payload":payload,"signature":JWS_Signature_tob64})
    jws_final = jws_final.replace(" ", "") 


    downloadRequest = requests.post(url=downloadURL, headers = headers, data=jws_final, verify=PEBBLE_CERTIFICATE_PATH)
    return downloadRequest, downloadRequest.headers, downloadRequest.text



def revoke_certificate(newAccountHeader, previousHeader, keyPriv, cert, urldirectory):

    prevHeader = jsonify(previousHeader)
    kidFromAccount = jsonify(newAccountHeader)

    previousNonce = json.loads(prevHeader).get('Replay-Nonce') 
    kidLocation = json.loads(kidFromAccount).get('Location')

   
    newAccountJson = jsonify(urldirectory)
    revokeCert_url = json.loads(newAccountJson).get('revokeCert') 
   

    headers = {"Content-type":"application/jose+json"}

    cert = open("downloadedCertificate.pem", "rb").read()

    certDER = x509.load_pem_x509_certificate(cert)

    certDerEncode = certDER.public_bytes(encoding=serialization.Encoding.DER)

    certDerEncodeBase64 = base64.urlsafe_b64encode(certDerEncode).decode('utf-8').rstrip("=")

    protected={"alg":"ES256",
               "kid":kidLocation,
               "nonce":previousNonce,
               "url":revokeCert_url}
    
    payload ={"certificate": certDerEncodeBase64}

    encoded_header = urlsafe_base64_encoding(protected)
    encoded_payload = urlsafe_base64_encoding(payload)

    sig_in = f"{encoded_header}.{encoded_payload}".encode('utf-8')
    JWS_Signature_tob64 = jws_generation(keyPriv, sig_in)

    jws_final = json.dumps({"protected":encoded_header,"payload":encoded_payload,"signature":JWS_Signature_tob64})
    jws_final = jws_final.replace(" ", "") 



    revoke_Request = requests.post(revokeCert_url, headers = headers, data=jws_final, verify=PEBBLE_CERTIFICATE_PATH)

    print(f"revoke Status Code: {revoke_Request.status_code}")
    print(f"revoke Response Body: {revoke_Request.headers}")

    return revoke_Request.text







if __name__ == "__main__":
    # Hint: You may want to start by parsing command line arguments and
    # perform some sanity checks first. The built-in `argparse` library will suffice.

    global domains

    parser = argparse.ArgumentParser(description="argument parser")
    parser.add_argument('command', choices=['dns01', 'http01'], help="command to run")
    parser.add_argument('--dir', type=str, required=True, help="directlory URL like https://example.com/dir")
    parser.add_argument('--record', type=str, required=True, help="DNS record like 1.2.3.4")
    parser.add_argument('--domain', type=str, required=True, action='append', help="Domains for challenge")
    parser.add_argument('--revoke', action="store_true", help="Revoke the certificate") 

    arguments = parser.parse_args()
    print(f"Command: {arguments.command}")
    print(f"Directory: {arguments.dir}")
    print(f"DNS Record: {arguments.record}")
    print(f"Domains: {arguments.domain}")
    print(f"Revoke: {arguments.revoke}")
    domains = arguments.domain
    record = arguments.record
    global chall_type 
    chall_type = arguments.command




    http01_server = HTTPServer((record, 5002), HTTP01Handler)
    dns01_server = DNSServer(DNS01Handler(ip_addr=record), port=10053, address=record)
    shutdown_server = HTTPServer((record, 5003), SHUTDOWN_SERVER)


    # Hint: You will need more HTTP servers

    http01_thread = Thread(target = http01_server.serve_forever)
    dns01_thread = Thread(target = dns01_server.server.serve_forever)
    shutdown_thread = Thread(target = shutdown_server.serve_forever)
    http01_thread.daemon = True
    dns01_thread.daemon = True
    shutdown_thread.daemon = True

    http01_thread.start()
    dns01_thread.start()
    shutdown_thread.start()

    print("HTTP server is running on http://localhost:5002")

    

   
    
    directory = acme_get_directory(arguments.dir)
    if directory:
        print(" 1. ACME Directory response : ")
        print(directory)
    
    #Getting a newNonce from ACME server
    newNonce = acme_get_newNonce(directory)
    print(" 2. ACME newNonce request response : ")
    print(newNonce)


    # #Create account on ACME server
    newAccount, newAccHeaders, priv, pub = acme_create_account(newNonce, directory)
    print(" 3. ACME create Account request response : ")
    print(newAccount)

    # #New Order Request
    newOrder, newOrderHeaders= acme_post_order(directory, newAccount, newAccHeaders, priv, pub, domains)
    print("4. newOrder request response : ")
    print(newOrder)

    polling, pollingHeader, validated_domains = polling_multi(newOrder, newAccHeaders, newOrderHeaders, priv, domains)

  
    print("text", polling)
    print("header", pollingHeader)

    csr_request, csr_requestHeaders, newKey = csr(newOrder,newOrderHeaders, pollingHeader, newAccHeaders,  priv, validated_domains)
    print ("csr_request", csr_request)


    download, downloadHeader, downloadText = downloadCertificate(newOrder,csr_request, csr_requestHeaders, newAccHeaders,  priv, domains)


    print(type(downloadText))
    print(downloadText)



    with open("newKey.pem", "wb") as key_file:
        key_file.write(newKey.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.PKCS8,
                                            encryption_algorithm=serialization.NoEncryption()))
        
    

    
    with open("downloadedCertificate.pem", "wb") as cert:
        cert.write(downloadText.encode('utf-8'))

    keyfile  = '/newKey.pem'
    certfile = '/downloadedCertificate.pem'

    certificate_HTTP_server = HTTPServer((record, 5001), CERTIFICATE_HTTP_server)

    cert_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_ssl_context.load_cert_chain(certfile='downloadedCertificate.pem', keyfile='newKey.pem')

    cert_ssl_context.check_hostname = False
    certificate_HTTP_server.socket = cert_ssl_context.wrap_socket(certificate_HTTP_server.socket,server_side = True,
                                              )
    

    cert_server_thread = Thread(target = certificate_HTTP_server.serve_forever)
    
    cert_server_thread.daemon = True

    cert_server_thread.start()

    if arguments.revoke:
        revoked = revoke_certificate(newAccHeaders, downloadHeader, priv , certfile, directory)
        print(revoked)



    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Server interrupted, shutting down.")
        http01_server.shutdown()

    # Your code should go here
