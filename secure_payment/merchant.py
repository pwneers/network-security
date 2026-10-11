import hashlib
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.exceptions import InvalidSignature

# load customers public key
with open("customer_public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# load merchant packet
with open("merchant_packet.json", "r") as f:
    packet = json.load(f)

print("Fields received by merchant:", list(packet.keys()))
print()

OI = packet["OI"]
PIMD = bytes.fromhex(packet["PIMD"])
DS = bytes.fromhex(packet["DS"])

# merchant calculates OIMD and POMD
OIMD = hashlib.sha256(OI.encode()).digest()
POMD = hashlib.sha256(PIMD + OIMD).digest()

print("OI (readable)  :", OI)
print("PIMD (hash only):", PIMD.hex())
print("Computed OIMD  :", OIMD.hex())
print("Computed POMD  :", POMD.hex())
print()

# signature verification
try:
    public_key.verify(DS, POMD, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    print("MERCHANT: Signature VALID")
except InvalidSignature:
    print("MERCHANT: Signature INVALID")
    