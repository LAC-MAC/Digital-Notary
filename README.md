# Digital-Notary
This application securely signs and verifies signatures to documents.


Each signatory would
have provided a signature of a given document using their own PGP certificate; the set of signato-
ries is then signed using a X.509 certificate which would have been specifically set for the document.
The application is capable of verifying the set of signatures to a given document. The application is
certified by a local Certification Authority (CA) which is also certifying the document’s certificate.
Context of use: the application is to be used by a Notary to witness signatures on documents. The
application should be implemented as a commandline client/server application with the notary server
distributing document, public certificate, signatory certification on request and accepting individual
signature. 
