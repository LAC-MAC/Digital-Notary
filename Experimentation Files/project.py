import sys
from cryptography import x509

certfile = sys.argv[1]
with open(certfile, "rb") as cf:
    certdata = cf.read()
certificate = x509.load_pem_x509_certificate(certdata)
print(str(certificate.version))
print("Valid: " + str(certificate.not_valid_before), end='')
print(" until " + str(certificate.not_valid_after))
print("issuer:" + str(certificate.issuer))
print("subject:" + str(certificate.subject))

