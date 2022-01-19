#!/usr/bin/env python3
import sys
import socket
from pgpy import PGPKeyring, PGPKey, PGPMessage, PGPSignature
import pickle
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

HOST = '137.195.15.201'  # The server's hostname or IP address
PORT = 6002     # The port used by the server



def pgpVerify(plaintext, pgpCertificates, pgpSignatures):

    for i in range(len(pgpCertificates)): 
        verifications = pgpCertificates[i].verify(plaintext,pgpSignatures[i])
        print(verifications)
        for signature in verifications.good_signatures:
            if signature.verified:
                print("Verified PGP signatures")
            else:
                print("Not Verified PGP signatures!")

def validate(signature, plaintext, pub):
    #try catch
    try:
        #verify
        pub.verify(signature, plaintext, padding.PKCS1v15(), hashes.SHA256()) 
        #confirm success
        print("validated")
    except InvalidSignature:
        #fail to validate
        print("An exception occurred")

def pgpSign(pgpkeyPath, document, passphrase):
    with open(pgpkeyPath, "r") as privatekeyfile:
        pkdata = privatekeyfile.read()
        privkey = PGPKey()
        privkey.parse(pkdata)
    
    pubkeyLoaded = privkey.pubkey

    print(privkey)
    # sign the file
    message = PGPMessage.new(document, file=True)
    with privkey.unlock(passphrase):
        signature = privkey.sign(message)
    print(signature)

    return signature, pubkeyLoaded

def verify():
    filename = input("Please enter a filename: ")
    s.sendall(bytes(filename, "utf-8"))

    # Recieves file, X509 certificate, X509 signatures
    verifyFile = s.recv(67072)
    
    print(verifyFile)

    #s.sendall(bytes("hello", "utf-8"))
    #if verifyFile.decode() == "400":
     #decode("utf-8")   print("Doesnt Exist")

    print("-------")
    x509Signature = s.recv(2048)
    print("this is the signature" ,x509Signature)

    print("CERTIFICATE TO FOLLOW:")
    x509Certificate =  x509.load_pem_x509_certificate(s.recv(2048))
    print(x509Certificate)

    pubKey_data = s.recv(4096)
    print("PUBLIC KEYS TO FOLLOW")
    print(pubKey_data)

    plaintext_data = s.recv(2048)
    print("PLAIN TEXT TO FOLLOW")
    print(plaintext_data)

    #load in certificate
    #cert = x509.load_pem_x509_certificate(x509Certificate)
    
    #get public key
    pub = x509Certificate.public_key()
    print(isinstance(pub, rsa.RSAPublicKey))
    # Verify X.509 signature
    validate(x509Signature, verifyFile, pub)
        
    listofsignatures = pickle.loads(verifyFile)

    
    for i in range(len(listofsignatures)):
        listofsignatures[i] = pickle.loads(listofsignatures[i])
   
    print(listofsignatures[0])
    
    listofpgpPublicKeys = pickle.loads(pubKey_data)

    for i in range(len(listofpgpPublicKeys)):
        publickey = PGPKey()
        listofpgpPublicKeys[i] = publickey.parse(listofpgpPublicKeys[i])
        listofpgpPublicKeys[i] = list(listofpgpPublicKeys[i].items())[0][1]
        #print(i ,"------",listofpgpPublicKeys[i])

        #print(listofpgpPublicKeys)

    pgpVerify(plaintext_data,listofpgpPublicKeys, listofsignatures )

    #print(listofpgpPublicKeys[0])

def sign():
    #client sends name of the file
    filename = input("Please enter a filename: ")
    s.sendall(bytes(filename, "utf-8"))
    #recieves file from server
    document = s.recv(2048)
    
    if document.decode() == "400":
        print("File does not exist")

    noSignatories = int(input("Please specify the number of signatories for this document: "))


    # catch floating point numbers
    while True:
        if noSignatories > 0:
            break
        noSignatories = int(input("Try again please select enter in the number of signatories: "))
    
    
    pkFilePaths = []
    passphrases = []

    for i in range(noSignatories):
        #asks for file path of pgp private key
        pkFilePaths.append(input("Please Specifiy the file path of the PGP private key: "))

        #asks for file path of pgp private key
        #pubFilePath = input("Please Specifiy the file path of the PGP public key   ")

        #asks for file path of pgp private key
        passphrases.append(input("Please enter your passphrase: "))

        #publickey, other = PGPKey.from_file(pubFilePath)

        #print(publickey)

    s.sendall(bytes(str(noSignatories), "utf-8"))
        
    for i in range(noSignatories):    
        #signs it
        signature, pubkey = pgpSign(pkFilePaths[i], document,passphrases[i]) 
        signature = pickle.dumps(signature)
        

        #sends signature to server
        s.sendall(signature)
        s.sendall(pubkey.__bytes__())

   
        
    
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    
    s.connect((HOST, PORT))
    print("You are connected to MusaLachLTD server")
    selectedFun = input("Select Verify or Sign:  ")
    selectedFun = selectedFun.lower()

    while True:
        if selectedFun  == "sign":
            break
        if selectedFun  == "verify":
            break
        if selectedFun  == "":
            break

        selectedFun = input("Try again please select Verify or Sign:  ")
        selectedFun = selectedFun.lower()
        

    s.sendall(bytes(selectedFun, "utf-8"))
    #CHECK selectedfun and trigger the corresponding method for whatever function
    if selectedFun == "verify":
        #call function for verify
        verify()
    else:
        #call function for sign
        sign()
        
    
s.close()

    
    
    