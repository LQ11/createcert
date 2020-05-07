import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

class create_cert(object):
    def rsa_ca(self,sign_hash_change):
        with open('rsa_ca.key', 'rb') as  key_file:
            key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
            )
            
        if sign_hash_change == 1:
            algorithm = hashes.MD5()
        elif sign_hash_change == 2:
            algorithm = hashes.SHA1()
        elif sign_hash_change == 3:
            algorithm = hashes.SHA224()
        elif sign_hash_change == 4:
            algorithm = hashes.SHA256()
        elif sign_hash_change == 5:
            algorithm = hashes.SHA512()

        subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"ShaanXi"),
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u"XiAN"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u"LQtest"),   
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"ca"),
        ])
        cert = x509.CertificateBuilder().subject_name(
        subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()
        ).not_valid_after(
        #设置证书有效期
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            extension = 
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False).add_extension(
            extension = 
        x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
        critical=False).add_extension(
            extension = 
        x509.BasicConstraints(ca=True, path_length=None), 
        critical=True).sign(key, algorithm, default_backend())

        with open("rsa_ca.crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def ecc_ca(self,sign_hash_change):
        with open('ecc_ca.key', 'rb') as  key_file:
            key = serialization.load_pem_private_key(
            key_file.read(),
            #加密key password='密码'
            password=None,
            backend=default_backend()
            )
        
        if sign_hash_change == 2:
            algorithm = hashes.SHA1()
        elif sign_hash_change == 3:
            algorithm = hashes.SHA224()
        elif sign_hash_change == 4:
            algorithm = hashes.SHA256()
        elif sign_hash_change == 5:
            algorithm = hashes.SHA512()

        subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"ShaanXi"),
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u"XiAN"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u"LQtest"),   
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"ca"),
        ])
        cert = x509.CertificateBuilder().subject_name(
        subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()
        ).not_valid_after(
        #设置证书有效期
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            extension = 
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False).add_extension(
            extension = 
        x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
        critical=False).add_extension(
            extension = 
        x509.BasicConstraints(ca=True, path_length=None), 
        critical=True).sign(key, algorithm, default_backend())

        with open("ecc_ca.crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    def rsa_cert(self,key_name,crt_name,issuer_name):
        with open(key_name + '.key', 'rb') as  key_file:
            key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
            )
        with open(issuer_name+'.crt','rb') as ca_file:
            ca_file = x509.load_pem_x509_certificate(
                ca_file.read(),
                backend=default_backend()
            )
        issuer = ca_file.subject

        subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"ShaanXi"),
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u"XiAN"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u"LQtest"),   
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"ca_" + crt_name),
        ])
        
        algorithm = ca_file.signature_hash_algorithm

        cert = cert = x509.CertificateBuilder().subject_name(
        subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()
        ).not_valid_after(
        #设置证书有效期
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            extension = 
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False).add_extension(
            extension = 
        x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
        critical=False).add_extension(
            extension = 
        x509.BasicConstraints(ca=True, path_length=None), 
        critical=True).sign(key, algorithm, default_backend())
        
        with open(crt_name + ".crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def ecc_cert(self,key_name,crt_name,issuer_name):
        with open(key_name + '.key', 'rb') as  key_file:
            key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
            )    

        with open(issuer_name+'.crt','rb') as ca_file:
            ca_file = x509.load_pem_x509_certificate(
                ca_file.read(),
                backend=default_backend()
            )
        
        issuer = ca_file.subject
        
        subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"ShaanXi"),
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u"XiAN"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u"LQtest"),   
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"ca_" + crt_name),
        ])
        
        algorithm = ca_file.signature_hash_algorithm

        cert = cert = x509.CertificateBuilder().subject_name(
        subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()
        ).not_valid_after(
        #设置证书有效期
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            extension = 
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False).add_extension(
            extension = 
        x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
        critical=False).add_extension(
            extension = 
        x509.BasicConstraints(ca=True, path_length=None), 
        critical=True).sign(key, algorithm, default_backend())

        with open(crt_name + ".crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
