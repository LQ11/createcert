from ca import *

if __name__ == '__main__':
    
    cert_type = int(input("证书类型：\n1：RSA\n2：ECC\n"))
    key_size_length_change = int(input("密钥长度：\n1：512 or prime256v1\n2：1024 or secp384r1\n3：2048 or secp521r1\n4：3072\n5：4096\n"))
    key_name = input("输入密钥名称")
    #ca_key_name = input("输入ca密钥名称，已有ca密钥时输入已有密钥名称，不带后缀，仅支持后缀为.key的密钥")
    ca_key_nme = 'ca'
    sign_hash_change = int(input("签名算法(ECC不支持md5)：\n1：md5\n2：sha1\n3：sha224\n4：sha256\n5：sha512\n"))
    cert_name = input("输入证书名称")
    #ca_cert_name = input("输入ca证书名称，已有ca证书时输入已有证书名称，不带后缀，仅支持后缀为.crt的证书")
    ca_cert_name = 'ca'
    #创建ca
    ca().new_ca(cert_type,ca_key_name,ca_cert_name,key_size_length_change,sign_hash_change)
    #签名
    ca().ca_issuer(cert_type,ca_key_name,ca_cert_name,key_size_length_change,cert_name)
    #创建crl
    ca().create_crl(cert_type,cert_name,ca_key_name,ca_cert_name)
    
