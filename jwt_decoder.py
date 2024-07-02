import jwt
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


certificate_pem  = open('blob.pem', 'r').read()
certificate = x509.load_pem_x509_certificate(certificate_pem.encode(), default_backend())
public_key = certificate.public_key()
with open('blob.jwt', 'r') as file:
    token = file.read()
    decoded_token = jwt.decode(token, key=public_key, verify=False, algorithms=['HS256'])
    print(type(decoded_token))
    
