import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from Crypto.Cipher import AES
from Crypto import Random
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.exceptions import InvalidSignature

#get values from command line
certfile_in = sys.argv[1]
plaintext_in = sys.argv[2]
privkey = sys.argv[3]

# Read plaintext, public key and private Key
with open(plaintext_in, "rb") as plaintext_file:
    plaintext = plaintext_file.read()

with open(certfile_in, "rb") as certfile:
    certdata = certfile.read()

with open(privkey, "rb") as privfile:
    privdata = privfile.read()

#load in certificate
cert = x509.load_pem_x509_certificate(certdata)

#load in private key
priv = load_pem_private_key(privdata, password=None)
#get public key
pub = cert.public_key()
#print(isinstance(pub, rsa.RSAPublicKey))

#mes = bytes("work please", 'utf-8')

#sign the plain text
signature = priv.sign(
    plaintext, 
    padding.PKCS1v15(), 
    hashes.SHA256()
)

def validate(signature, plaintext):
    #try catch
    try:
        #verify
        pub.verify(signature, plaintext, padding.PKCS1v15(), hashes.SHA256()) 
        #confirm success
        print("validated")
    except InvalidSignature:
        #fail to validate
        print("An exception occurred")


#verifiy certificate
validate(signature, plaintext)






