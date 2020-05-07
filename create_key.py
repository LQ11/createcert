from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec

class create_key(object):
    def rsa_key(self,key_size_length_change,key_name):
        if key_size_length_change == 1:
            key_size = 512
        elif key_size_length_change == 2:
            key_size = 1024
        elif key_size_length_change == 3:
            key_size = 2048
        elif key_size_length_change == 4:
            key_size = 3072           
        elif key_size_length_change == 5:
            key_size = 4096
        key = rsa.generate_private_key(public_exponent=65537,key_size=key_size,backend=default_backend())
        #保存私钥文件
        with open(key_name+".key","wb") as f:
            f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            #key是否加密
            # encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),))
            encryption_algorithm=serialization.NoEncryption(),))

    def ecc_key(self,key_size_length_change,key_name):
        if key_size_length_change == 1:
            curve = ec.SECP256R1()
        elif key_size_length_change == 2:
            curve = ec.SECP384R1()
        elif key_size_length_change == 3:
            curve = ec.SECP521R1()
        key = ec.generate_private_key(curve=curve,backend=default_backend())

        with open(key_name+".key","wb") as f:
            f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),))
