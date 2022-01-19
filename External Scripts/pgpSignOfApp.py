import sys
import socket
from pgpy import PGPKeyring, PGPKey, PGPMessage, PGPSignature
import pickle
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

pgpkeyPath = sys.argv[1]
plaintext = sys.argv[2]
passphrase = sys.argv[3]

with open(pgpkeyPath, "r") as privatekeyfile:
    pkdata = privatekeyfile.read()
    privkey = PGPKey()
    privkey.parse(pkdata)

with open(plaintext, "rb") as plaintextFile:
    plaintext_data = plaintextFile.read()

pubkeyLoaded = privkey.pubkey

# sign the file
message = PGPMessage.new(plaintext_data, file=True)
with privkey.unlock(passphrase):
    signature = privkey.sign(message)

signature = pickle.dumps(signature)


with open("./pgpSignaturesOfApp/" + "serverRecord" + "_PGPSignature.sig", "wb") as sigFile:
    sigFile.write(signature)