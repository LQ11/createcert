import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

class create_crl(object):
    def rsa_crl(self,crt_name,ca_key_name,ca_crt_name):
        #加载被吊销的证书
        with open(crt_name + '.crt','rb') as revoke_file:
            revoke_file = x509.load_pem_x509_certificate(
                revoke_file.read(),
                backend=default_backend()
            )
        #加载ca key
        with open(ca_key_name + '.key', 'rb') as  key_file:
            ca_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
            )
        #加载ca
        with open(ca_crt_name + '.crt','rb') as ca_file:
            ca_file = x509.load_pem_x509_certificate(
                ca_file.read(),
                backend=default_backend()
            )
        #获取ca subject和ca Signature Algorithm
        issuer = ca_file.subject
        algorithm = ca_file.signature_hash_algorithm
        
        crl = x509.CertificateRevocationListBuilder().issuer_name(
            issuer
            ).last_update(#创建时间
            datetime.datetime.utcnow()
            ).next_update(#失效时间
            datetime.datetime.utcnow() + datetime.timedelta(days = 3650)
            ).add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(
                revoke_file.serial_number
            ).revocation_date(
                datetime.datetime.utcnow()
            ).build(
                default_backend()
            )
            ).sign(ca_key,algorithm,backend=default_backend())
        #保存生成的crl
        with open(crt_name + '.crl','wb') as f:
            f.write(crl.public_bytes(encoding=serialization.Encoding.PEM,))


    def ecc_crl(self,crt_name,ca_key_name,ca_crt_name):
        #加载被吊销的证书
        with open(crt_name + '.crt','rb') as revoke_file:
            revoke_file = x509.load_pem_x509_certificate(
                revoke_file.read(),
                backend=default_backend()
            )
        #加载ca key
        with open(ca_key_name + '.key', 'rb') as  key_file:
            ca_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
            )
        #加载ca
        with open(ca_crt_name + '.crt','rb') as ca_file:
            ca_file = x509.load_pem_x509_certificate(
                ca_file.read(),
                backend=default_backend()
            )
        #获取ca subject和ca Signature Algorithm
        issuer = ca_file.subject
        algorithm = ca_file.signature_hash_algorithm
        
        crl = x509.CertificateRevocationListBuilder().issuer_name(
            issuer
            ).last_update(#创建时间
            datetime.datetime.utcnow()
            ).next_update(#失效时间
            datetime.datetime.utcnow() + datetime.timedelta(days = 3650)
            ).add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(
                revoke_file.serial_number
            ).revocation_date(
                datetime.datetime.utcnow()
            ).build(
                default_backend()
            )
            ).sign(ca_key,algorithm,backend=default_backend())
        #保存生成的crl
        with open(crt_name + '.crl','wb') as f:
            f.write(crl.public_bytes(encoding=serialization.Encoding.PEM,))
