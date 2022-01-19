#!/usr/bin/env python3

import socket
import pickle
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

HOST = '137.195.15.201'  # IP adddress of linux01
PORT = 6002  # Port to listen on (non-privileged ports are > 1023)

# This function handles the X.509 certificate signing the user specified document 
def x509Sign(filename):

    #open x509 private key
    with open("./x509PrivateKeys/" + filename+"_x509Pkey.pem", "rb") as privfile:
        # Read the private key
        privdata = privfile.read()

    # Open the list of signed PGP certificates
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

        # Print error   
        except:
            print("ERROR - Could not send list")
    # Send a error message
    except:
        conn.sendall(bytes("400", "utf-8"))
        print("File does not exist")

    try:
        with open("./x509Signatures/" + filename + "_x509Signature.sig", "rb") as x509Signature_file:
            x509Signature = x509Signature_file.read()
            x509Signature_file.close()
            print("---------")
            print(x509Signature)
        try:
            conn.sendall(x509Signature)
            
        except Exception as e:
            print(e)
            print("couldnt send signature")
    except:
        conn.sendall(bytes("400", "utf-8"))
        
        print("doesnt exist")

    try:
        with open("./x509Certificates/" + filename + ".pem", "rb") as x509Certificates_file:
            certificateData = x509Certificates_file.read()
            x509Certificates_file.close()
            print("---------")
            #print(certificateData)
        
        try:
            conn.sendall(certificateData)
        except Exception as e:
            print(e)
            print("could not send certificates")
    except:
        print("something went horribly wrong")

    try:
        # Open the list of PGP certificates to read
        with open("./PGPCertificates/" + filename+"_PGPCertificates.pkl", "rb") as pgpCertificates_data:
            pgpCertificates = pgpCertificates_data.read()
            pgpCertificates_data.close()
        try:
            conn.sendall(pgpCertificates)
        except Exception as e:
            print(e)
            print("Could not send PGP Certificates")
    except: 
        print("There was a disturbance in the code...Check your pickles")

    try:
        # Open the list of PGP certificates to read
        with open("./documents/" + filename+"_doc.txt", "rb") as plaintext_data:
            plaintext = plaintext_data.read()
            plaintext_data.close()
        try:
            conn.sendall(plaintext)
        except Exception as e:
            print(e)
            print("Could not send plain text")
    except: 
        print("There was a disturbance in the code...Check your pickles:revenge of the oninos")




def record():

    filename = conn.recv(1024)
    filename = filename.decode()

    try:
        signatures = pickle.load(open("./lists/" + filename+"_list.pkl", "rb"))
        #for i in range(len(signatures)):
            #signatures[i] = pickle.loads(signatures[i])
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
        
        print("doesnt exist")


    noSignatories_bytes = conn.recv(1024)
    noSignatories = int(noSignatories_bytes.decode("utf-8"))

    for i in range(noSignatories):
        signature = conn.recv(4096)
        print("this is signature", signature)
        signatures.append(signature)
        pubkey = conn.recv(4096)
        print("this is pubkey", pubkey)
        pgpCertificates.append(pubkey)
        
    #signature = pickle.loads(conn.recv(1024))
    

    pickle.dump(signatures, open("./lists/" + filename+"_list.pkl", "wb"))
    pickle.dump(pgpCertificates, open("./PGPCertificates/" +filename+"_PGPCertificates.pkl", "wb"))
    
    #newarr = pickle.load(open("./lists/" + filename+"_list.pkl", "rb"))
    #for i in range(len(newarr)):
            #print("this is it", newarr[i])
            #newarr[i] = pickle.loads(newarr[i])
    #print(newarr[0])
    x509Sign(filename)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

    s.bind((HOST, PORT))
    s.listen()
    print("Server active, waiting for connections...")
    conn, addr = s.accept()
    
    with conn:
        print("connected by: ", addr)
        
        operation = conn.recv(1024)
        
        if operation.decode() == "verify":
            print("LOG: User requested 'Verify' command")
            verify(conn)     
            
        else:
            print("LOG: User requested 'Sign' command")
            record()


s.close()

