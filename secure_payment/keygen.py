from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# rsa keygen - PK (2048 bits)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# generate the public key out of the private key
public_key = private_key.public_key()

# convert keys into PEM format in order to save them into
# files to be used later from the rest of the scripts
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM, # this will generate the key file in Base64 Format
    format=serialization.PrivateFormat.PKCS8, # common key storage format
    encryption_algorithm=serialization.NoEncryption(), 
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# printing the keys inside files
with open("customer_private.pem", "wb") as f:
    f.write(private_pem)

with open("customer_public.pem", "wb") as f:
    f.write(public_pem)

print("RSA key pair generated (2048 bits)")
print("Private key saved to: customer_private.pem")
print("Public key saved to:  customer_public.pem")
print()
print(public_pem.decode())
