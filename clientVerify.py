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
PORT = 6001    # The port used by the server

# This method is for the verification of the pgp signatures 
# of a given document. It takes the orginal document, the list 
# of PGP Certificates and the list of PGP Signatures of the document.
def pgpVerify(plaintext, pgpCertificates, pgpSignatures):
    #loop for how many certificiates there is
    for i in range(len(pgpCertificates)): 
        #assign the results of the verification of signatures to an variable
        verifications = pgpCertificates[i].verify(plaintext,pgpSignatures[i])
        print("-> Verifying PGP Signature "+ str(i+1) + "...")
        #for all of the results of the verification 
        for signature in verifications.good_signatures:
            #if result is verified
            if signature.verified:
                print("-> Signature was verified by PGP certificate with Fingerprint : " +pgpCertificates[i].fingerprint )
            else:
                #if result is not verified
                print("Not Verified a PGP signature!")

# This method is for the verification of the X509 signature of the list of
# signatures for a document. It takes the x509 signature, the list of signatures
# and the X509 public key
def validate(signature, plaintext, pub):
    #try catch
    try:
        #verify
        pub.verify(signature, plaintext, padding.PKCS1v15(), hashes.SHA256()) 
        #confirm success
        print("-> X.509 signature verified")
    except InvalidSignature:
        #fail to validate
        print("-> Unable to validate X.509 signature")


#This method is for the signing of a document with a PGP private key.
# It takes the path to the PGP private Key, the document and the passphrase
# associated with the private key
def pgpSign(pgpkeyPath, document, passphrase):
    with open(pgpkeyPath, "r") as privatekeyfile:
        pkdata = privatekeyfile.read()
        privkey = PGPKey()
        privkey.parse(pkdata)
    
    pubkeyLoaded = privkey.pubkey

    # sign the file
    message = PGPMessage.new(document, file=True)
    with privkey.unlock(passphrase):
        signature = privkey.sign(message)

    return signature, pubkeyLoaded



# This method is for when the client wishes to verify a document
# It asks the client for the specific document
# Recieves the list of PGP signatures for the specific document
# Recieves the x509 signature
# Recieves the x509 certificate
# Recieves the list of PGP certificates for the specific document
# Recieves the original document
def verify():
    filename = input("Please enter a filename: ")
    s.sendall(bytes(filename, "utf-8"))

    # Recieves file, X509 certificate, X509 signatures
    verifyFile = s.recv(67072)
    
    print("-> List of signatures recieved")
    x509Signature = s.recv(2048)

    x509Certificate =  x509.load_pem_x509_certificate(s.recv(2048))

    print ("-> X.509 details recieved") 
    
    pubKey_data = s.recv(4096)
    print("-> Public keys recieved")

    plaintext_data = s.recv(2048)
    print("-> " + filename + " recieved")

    #load in certificate    
    #get public key
    pub = x509Certificate.public_key()
    print("-> X.509 public key extracted")
    # Verify X.509 signature
    validate(x509Signature, verifyFile, pub)
        
    listofsignatures = pickle.loads(verifyFile)

    for i in range(len(listofsignatures)):
        listofsignatures[i] = pickle.loads(listofsignatures[i])
       
    listofpgpPublicKeys = pickle.loads(pubKey_data)

    for i in range(len(listofpgpPublicKeys)):
        publickey = PGPKey()
        listofpgpPublicKeys[i] = publickey.parse(listofpgpPublicKeys[i])
        listofpgpPublicKeys[i] = list(listofpgpPublicKeys[i].items())[0][1]

    pgpVerify(plaintext_data,listofpgpPublicKeys, listofsignatures )


# This method is for when a client wishes to sign a specfic document 
# with one or more PGP private keys
# Creates a signature for each private key and sends to the server
def sign():
    #client sends name of the file
    filename = input("Please enter a filename: ")
    s.sendall(bytes(filename, "utf-8"))
    #recieves file from server
    document = s.recv(2048)
    
    if document.decode() == "400":
        print("File does not exist")


    # catch floating point numbers
    while True:
        try:     
            noSignatories = int(input("Please specify the number of signatories for this document: "))
        except ValueError:
            print("Not an integer! Try again.")
            continue
        if noSignatories > 0:
            break
        print("Must be a positive integer! Try again.")
    
    
    pkFilePaths = []
    passphrases = []

    for i in range(noSignatories):
        #asks for file path of pgp private key
        pkFilePaths.append(input("Please specifiy the file path of the PGP private key: "))

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

    print("Document successfully signed")

   
        
    
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #connect
    s.connect((HOST, PORT))
    #welcome and ask for input
    print("You are connected to MusaLachLTD server")
    selectedFun = input("Select Verify or Sign:  ")
    selectedFun = selectedFun.lower()
    #check input is correct
    while True:
        if selectedFun  == "sign":
            break
        if selectedFun  == "verify":
            break
        if selectedFun  == "":
            break

        selectedFun = input("Try again please select Verify or Sign:  ")
        selectedFun = selectedFun.lower()
        
    #send selected mode
    s.sendall(bytes(selectedFun, "utf-8"))
    #CHECK selectedfun and trigger the corresponding method for whatever function
    if selectedFun == "verify":
        #call function for verify
        verify()
    else:
        #call function for sign
        sign()
        
    
s.close()

    
    
    
