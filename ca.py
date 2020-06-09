from create_key import *
from create_cert import *
from create_crl import *
from create_ca import *

class ca(object):
    def new_ca(self,cert_type,ca_key_name,ca_cert_name,key_length,sign_hash):
        if cert_type == 1:
            create_key().rsa_key(key_length,ca_key_name)
            create_ca().rsa_ca(ca_key_name,ca_cert_name,sign_hash)
        elif cert_type == 2:
            create_key().ecc_key(key_length,ca_key_name)
            create_ca().ecc_ca(ca_key_name,ca_cert_name,sign_hash)
    
    def ca_issuer(self,cert_type,ca_key_name,ca_cert_name,key_length,crt_name):
        if cert_type == 1:
            create_key().rsa_key(key_length,crt_name)
            create_cert().rsa_cert(crt_name,ca_key_name,ca_cert_name)
        elif cert_type == 2:
            create_key().ecc_key(key_length,crt_name)
            create_cert().ecc_cert(crt_name,ca_key_name,ca_cert_name)

    def create_crl(self,cert_type,crt_name,ca_key_name,ca_cert_name):
        if cert_type == 1:
            create_crl().rsa_crl(crt_name,ca_key_name,ca_cert_name)
        elif cert_type == 2:
            create_crl().ecc_crl(crt_name,ca_key_name,ca_cert_name)
