
import sys
import socket
import pickle
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

plaintext= sys.argv[1]

#open x509 private key
with open("./x509PrivateKeys/" + "doc1"+"_x509Pkey.pem", "rb") as privfile:
    # Read the private key
    privdata = privfile.read()

with open(plaintext, "rb") as plaintextFile:
    plaintext_data = plaintextFile.read()

#load in private key
priv = load_pem_private_key(privdata, password=None)

#sign the plain texts
x509Signature = priv.sign(
    plaintext_data, 
    padding.PKCS1v15(), 
    hashes.SHA256()
)

# Write the X509 signature to an external .sig file
with open("./x509SignaturesOfDocuments/" + "doc1" + "_x509Signature.sig", "wb") as sigFile:
    sigFile.write(x509Signature)