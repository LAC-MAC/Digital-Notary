#!/usr/bin/env python3

import socket
import pickle
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

HOST = '137.195.15.201'  # IP adddress of linux01
PORT = 6001  # Port to listen on (non-privileged ports are > 1023)

# This function handles the X.509 certificate signing the user specified document 
def x509Sign(filename):

    #open x509 private key
    with open("./x509PrivateKeys/" + filename+"_x509Pkey.pem", "rb") as privfile:
        # Read the private key
        privdata = privfile.read()

    # Open the list of PGP signatures
    with open("./lists/" + filename+"_list.pkl", "rb") as listfile:
        listdata = listfile.read()

    #load in private key
    priv = load_pem_private_key(privdata, password=None)

    #sign the plain text
    x509Signature = priv.sign(
        listdata, 
        padding.PKCS1v15(), 
        hashes.SHA256()
    )
    
    # Write the X509 signature to an external .sig file
    with open("./x509Signatures/" + filename + "_x509Signature.sig", "wb") as sigFile:
        sigFile.write(x509Signature)

# This method sends to the client the information needed by the client to verify
# Sends the list of PGP signatures for the specific document
# Sends the x509 signature
# Sends the x509 certificate
# Sends the list of PGP certificates for the specific document
# Sends the original document
def verify(conn):
    
    # Recieve the filename from the client
    filename = conn.recv(1024)
    
    # Decode the filename
    filename = filename.decode()
    
    try:
        # Open the list of PGP signatures to read
        with open("./lists/" + filename+"_list.pkl", "rb") as plaintext_file:
            list_signatures = plaintext_file.read()
            plaintext_file.close()
        try:
            conn.sendall(list_signatures)
            print("LOG: PGP signatures sent to client")

        # Print error   
        except:
            print("ERROR - Could not send list")
    # Send a error message
    except:
        conn.sendall(bytes("400", "utf-8"))
        print("File does not exist")
        return None

    try:
        with open("./x509Signatures/" + filename + "_x509Signature.sig", "rb") as x509Signature_file:
            x509Signature = x509Signature_file.read()
            x509Signature_file.close()
            print("LOG: X.509 signature retrieved from file")
        try:
            conn.sendall(x509Signature)
            print("LOG: X.509 signature sent to client")
            
        except Exception as e:
            print(e)
            print("couldnt send signature")
            return None
    except:
        conn.sendall(bytes("400", "utf-8"))
        print("File does not exist")
        return None

    try:
        with open("./x509Certificates/" + filename + ".pem", "rb") as x509Certificates_file:
            certificateData = x509Certificates_file.read()
            x509Certificates_file.close()
            print("LOG: X.509 certificate retrieved from file")
        
        try:
            conn.sendall(certificateData)
            print("LOG: X.509 certificate sent to client")
        except Exception as e:
            print(e)
            conn.sendall(bytes("400", "utf-8"))
            print("could not send certificates")
            return None
    except:
        conn.sendall(bytes("400", "utf-8"))
        print("File does not exist")
        return None
        

    try:
        # Open the list of PGP certificates to read
        with open("./PGPCertificates/" + filename+"_PGPCertificates.pkl", "rb") as pgpCertificates_data:
            pgpCertificates = pgpCertificates_data.read()
            pgpCertificates_data.close()
            print("LOG: PGP certificates retrieved from file")

        try:
            conn.sendall(pgpCertificates)
            print("LOG: PGP certificates sent to client")

        except Exception as e:
            print(e)
            conn.sendall(bytes("400", "utf-8"))
            print("Could not send PGP Certificates")
            return None
    except: 
        conn.sendall(bytes("400", "utf-8"))
        print("File does not exist")
        return None

    try:
        # Open the plain text to read
        with open("./documents/" + filename+"_doc.txt", "rb") as plaintext_data:
            plaintext = plaintext_data.read()
            plaintext_data.close()
            print("LOG: Original document retrieved from file")
        try:
            conn.sendall(plaintext)
            print("LOG: Original document sent to client")
        except Exception as e:
            print(e)
            print("Could not send plain text")
            return None
    except: 
        conn.sendall(bytes("400", "utf-8"))
        print("File does not exist")
        return None

#This method recieves one or more PGP signatures and PGP certificates
# and adds each to there corresponding list
# it also creates a x509 signature of the list of PGP signatures 
def record():

    filename = conn.recv(1024)
    filename = filename.decode()

    try:
        signatures = pickle.load(open("./lists/" + filename+"_list.pkl", "rb"))
    except:
        signatures = []

    try: 
        pgpCertificates = pickle.load(open("./PGPCertificates/" +filename+"_PGPCertificates.pkl", "rb"))
    except:
        pgpCertificates = []
     
    try:
        with open("./documents/" + filename+"_doc.txt", "rb") as plaintext_file:
            plaintext = plaintext_file.read()
            plaintext_file.close()
            
        try:
            conn.sendall(plaintext)
            
        except:
            print("couldnt send")
    except:
        conn.sendall(bytes("400", "utf-8"))
        print("File does not exist")

    noSignatories_bytes = conn.recv(1024)
    noSignatories = int(noSignatories_bytes.decode("utf-8"))

    for i in range(noSignatories):
        signature = conn.recv(4096)
        print("LOG: Signature recieved")
        signatures.append(signature)
        pubkey = conn.recv(4096)
        print("LOG: Public key recieved")
        pgpCertificates.append(pubkey)
   

    pickle.dump(signatures, open("./lists/" + filename+"_list.pkl", "wb"))
    pickle.dump(pgpCertificates, open("./PGPCertificates/" +filename+"_PGPCertificates.pkl", "wb"))

    x509Sign(filename)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #creation of socket and set to listen
    s.bind((HOST, PORT))
    s.listen()
    #accept connections
    print("Server active, waiting for connections...")
    conn, addr = s.accept()
    
    with conn:
        print("connected by: ", addr)
        #recieve operation
        operation = conn.recv(1024)
        #trigger corresponding method
        if operation.decode() == "verify":
            print("LOG: User requested 'Verify' command")
            verify(conn)     
            
        else:
            print("LOG: User requested 'Sign' command")
            record()


s.close()

