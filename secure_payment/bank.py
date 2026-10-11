import hashlib
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.exceptions import InvalidSignature

# Load customer public key
with open("customer_public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# load bank packet
with open("bank_packet.json", "r") as f:
    packet = json.load(f)

print("Fields received by bank:", list(packet.keys()))
print()

PI = packet["PI"]
OIMD = bytes.fromhex(packet["OIMD"])
DS = bytes.fromhex(packet["DS"])

# bank calculates PIMD and POMD
PIMD = hashlib.sha256(PI.encode()).digest()
POMD = hashlib.sha256(PIMD + OIMD).digest()

print("PI (readable)   :", PI)
print("OIMD (hash only):", OIMD.hex())
print("Computed PIMD   :", PIMD.hex())
print("Computed POMD   :", POMD.hex())
print()

# signature verification with the public key
try:
    public_key.verify(DS, POMD, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    print("BANK: Signature VALID")
except InvalidSignature:
    print("BANK: Signature INVALID")
    