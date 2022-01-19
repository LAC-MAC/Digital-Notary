import base64, textwrap, sys
import jks
from Crypto import Random 
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import OpenSSL

ASN1 = OpenSSL.crypto.FILETYPE_ASN1



def print_pem(cert_bytes):
    print("-----BEGIN CERTIFICATE-----")
    encoded = base64.b64encode(cert_bytes).decode('ascii')
    wrapped = textwrap.wrap(encoded, 76)
    for line in wrapped:
        print(line)
    print("-----END CERTIFICATE-----")

def loadKeyStore():   
    keystorefile = sys.argv[1]
    keystorepassphrase = sys.argv[2]    
    keystore = jks.KeyStore.load(keystorefile,keystorepassphrase, try_decrypt_keys=True)
    return keystore

keystore = loadKeyStore()

print(str(keystore.store_type))
print(str(len(keystore.entries)))
print(str(len(keystore.certs)))
print(str(len(keystore.private_keys)))
#print(str(len(keystore.secret_keys)))

print(keystore.private_keys.items())

keys = []
for alias, key in keystore.private_keys.items():
    if not key.is_decrypted():
        key.decrypt("lachlan")
    print(str(alias))
    print(str(key.pkey))

    
    #print(isinstance(priv, rsa.RSAPrivateKey))
    pkey = OpenSSL.crypto.load_privatekey(ASN1, key.pkey_pkcs8)
    keys.append(pkey)
    print(pkey)
    #pkey = bytes(pkey, 'utf-8')
    #priv = load_pem_private_key(pkey, password=None)


for alias, cert in keystore.certs.items():
    print_pem(cert.cert)


message = "hello"

#signer = DSS.new(keys[1].pkey, 'fips-186-3')
#signature = signer.sign(message)

#f = open("encrptedDoc.txt", "w")
#f.write(signature)






