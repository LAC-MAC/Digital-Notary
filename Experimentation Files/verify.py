import sys
from pgpy import PGPKeyring, PGPKey, PGPMessage, PGPSignature
import json
import pickle


plaintext = sys.argv[1]
privatekey_file = sys.argv[2]
priv_passphrase = sys.argv[3]
public_key = sys.argv[4]
#signatures = sys.argv[5]

try:
    signatures = pickle.load(open("pickledSignatures.pkl", "rb"))
except:
    signatures = []


# get the key from the keyring

with open(privatekey_file, "r") as privatekeyfile:
    pkdata = privatekeyfile.read()
privkey = PGPKey()
privkey.parse(pkdata)



# sign the file
message = PGPMessage.new(plaintext, file=True)
with privkey.unlock(priv_passphrase):
    signature = privkey.sign(message)
    
    #turn signature in to its asc eqiv
    #add to array
    signatures.append(pickle.dumps(signature))
    
    #print(sig)

# write the signature
#with open("signatures" +'.txt', "w") as sigfile:
#sigfile.write(str(signature))



pickle.dump(signatures, open("pickledSignatures.pkl", "wb"))

#you can serialise an array but signature
# you can serialise signature 
#not both figure that one out

newarr = pickle.load(open("pickledSignatures.pkl", "rb"))
for i in range(len(newarr)):
    newarr[i] = pickle.loads(newarr[i])


print(newarr[0].signer)


publickey = PGPKey() 
with open(public_key, "r") as certfile:
    publickey.parse(certfile.read())

with open(plaintext, "r") as plainfile:
    file_message = plainfile.read()




verifications = publickey.verify(file_message,newarr[0])
print(verifications)
for signature in verifications.good_signatures:
    if signature.verified:
        print("Verified")
        exit()

print("Not Verified!")









