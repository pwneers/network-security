from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
import time

def create_rsa_signature(exp, key_size, msg) -> bytes:
   private_key = rsa.generate_private_key(exp, key_size)
   sign_beg = time.monotonic()
   signature = private_key.sign(
        data=msg,
        padding=padding.PSS(
            mgf=padding.MGF1(SHA256()),
            salt_length=padding.PSS.MAX_LENGTH    
        ), 
        algorithm=SHA256())
   duration = time.monotonic() - sign_beg
   return signature, duration

 
def create_dsa_signature(key_size, msg):
    private_key = dsa.generate_private_key(key_size)
    sign_beg = time.monotonic()
    signature = private_key.sign(data=msg, algorithm=SHA256())
    duration = time.monotonic() - sign_beg
    return signature, duration
    

def create_ecdsa_signature(msg):
   private_key = ec.generate_private_key(ec.SECP384R1())
   sign_beg = time.monotonic()
   signature = private_key.sign(msg, ec.ECDSA(SHA256()))
   duration = time.monotonic() - sign_beg
   return signature, duration


if __name__ == "__main__":
    msg = b"Hello, I am a message. You are not"
    
    
    rsa_signature, rsa_time = create_rsa_signature(65537, 2048, msg)
    dsa_signature, dsa_time = create_dsa_signature(2048, msg)
    ecdsa_signature, ecdsa_time = create_ecdsa_signature(msg)
    
    print(f"RSA signature length: {len(rsa_signature)}\t Time: {rsa_time}")
    print(f"DSA signature length: {len(dsa_signature)}\t Time: {dsa_time}")
    print(f"ECDSA signature length: {len(ecdsa_signature)}\t Time: {ecdsa_time}")
