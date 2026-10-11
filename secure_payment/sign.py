import hashlib
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils

PI = "Pay 100 DKK to MerchantX" # PI
OI = "Order #2456: 2 items total 100 DKK" # OI

# read the private key from the PEM file created in keygen,py
with open("customer_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# hashing the 2 messages
PIMD = hashlib.sha256(PI.encode()).digest()
OIMD = hashlib.sha256(OI.encode()).digest()

# combining the 2 hashes into a single hash
POMD = hashlib.sha256(PIMD + OIMD).digest()

# signing the combined hash with the PK
DS = private_key.sign(POMD, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))

# creating a dictionary with what the merchant and the bank will get
merchant_packet = {"OI": OI, "PIMD": PIMD.hex(), "DS": DS.hex()}
bank_packet = {"PI": PI, "OIMD": OIMD.hex(), "DS": DS.hex()}

with open("merchant_packet.json", "w") as f:
    json.dump(merchant_packet, f, indent=2)

with open("bank_packet.json", "w") as f:
    json.dump(bank_packet, f, indent=2)

#printing results
print("PI   :", PI)
print("OI   :", OI)
print("PIMD :", PIMD.hex())
print("OIMD :", OIMD.hex())
print("POMD :", POMD.hex())
print("--------------------------------")
print("Dual Signature (", len(DS), "bytes ):")
print(DS.hex())
print("--------------------------------")
print("merchant_packet.json -> OI + PIMD + DS")
print("bank_packet.json     -> PI + OIMD + DS")