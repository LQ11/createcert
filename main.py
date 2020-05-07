from create_key import *
from create_cert import *
from create_crl import *

if __name__ == '__main__':
    cert_type = int(input("证书类型：\n1：RSA\n2：ECC\n"))
    key_size_length_change = int(input("密钥长度：\n1：512 or prime256v1\n2：1024 or secp384r1\n3：2048 or secp521r1\n4：3072\n5：4096\n"))
    key_name = input("输入密钥名称")
    sign_hash_change = int(input("签名算法(ECC不支持md5)：\n1：md5\n2：sha1\n3：sha224\n4：sha256\n5：sha512\n"))
    crt_name = input("输入证书名称")

    if cert_type == 1:
        create_key().rsa_key(key_size_length_change,key_name = 'rsa_ca')
        create_key().rsa_key(key_size_length_change,key_name = key_name)
        create_key().rsa_key(key_size_length_change,key_name = key_name + '_level1')
        create_key().rsa_key(key_size_length_change,key_name = key_name + '_level2')
        create_key().rsa_key(key_size_length_change,key_name = key_name + '_level3')
        create_key().rsa_key(key_size_length_change,key_name = key_name + '_revoke')
        create_cert().rsa_ca(sign_hash_change)
        create_cert().rsa_cert(key_name,crt_name,'rsa_ca')
        create_cert().rsa_cert(key_name + '_level1',crt_name+ '_level1','rsa_ca')
        create_cert().rsa_cert(key_name + '_level2',crt_name+ '_level2',crt_name + '_level1')
        create_cert().rsa_cert(key_name + '_level3',crt_name+ '_level3',crt_name + '_level2')
        create_cert().rsa_cert(key_name + '_revoke',crt_name+ '_revoke','rsa_ca')
        create_crl().rsa_crl(crt_name)
    elif cert_type == 2:
        create_key().ecc_key(key_size_length_change,key_name = 'ecc_ca')
        create_key().ecc_key(key_size_length_change,key_name = key_name)
        create_key().ecc_key(key_size_length_change,key_name = key_name + '_level1')
        create_key().ecc_key(key_size_length_change,key_name = key_name + '_level2')
        create_key().ecc_key(key_size_length_change,key_name = key_name + '_level3')
        create_key().ecc_key(key_size_length_change,key_name = key_name + '_revoke')
        create_cert().ecc_ca(sign_hash_change)
        create_cert().ecc_cert(key_name,crt_name,'ecc_ca')
        create_cert().ecc_cert(key_name + '_level1',crt_name+ '_level1','ecc_ca')
        create_cert().ecc_cert(key_name + '_level2',crt_name+ '_level2',crt_name + '_level1')
        create_cert().ecc_cert(key_name + '_level3',crt_name+ '_level3',crt_name + '_level2')
        create_cert().ecc_cert(key_name + '_revoke',crt_name+ '_revoke','ecc_ca')
        create_crl().ecc_crl(crt_name)

