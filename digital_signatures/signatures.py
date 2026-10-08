from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
import time


# --- performance: time taken to generate the signature ---
def create_rsa_signature(exp, key_size, msg):
    key = rsa.generate_private_key(exp, key_size)
    t = time.monotonic()
    sig = key.sign(msg, padding.PSS(padding.MGF1(SHA256()), padding.PSS.MAX_LENGTH), SHA256())
    return sig, time.monotonic() - t


def create_dsa_signature(key_size, msg):
    key = dsa.generate_private_key(key_size)
    t = time.monotonic()
    sig = key.sign(msg, SHA256())
    return sig, time.monotonic() - t


def create_ecdsa_signature(msg):
    key = ec.generate_private_key(ec.SECP384R1())
    t = time.monotonic()
    sig = key.sign(msg, ec.ECDSA(SHA256()))
    return sig, time.monotonic() - t


# --- computational cost: the dominant step is one exponentiation / scalar
# multiplication. The binary method does, for an L-bit exponent, ~L squarings
# plus ~L/2 multiplications, i.e. O(L) group operations (O(L*n^2) bit ops). ---
def binary_method_ops(exp_bits):
    return exp_bits + exp_bits // 2


if __name__ == "__main__":
    msg = b"Hello, I am a message. You are not"

    rsa_sig, rsa_t = create_rsa_signature(65537, 2048, msg)
    dsa_sig, dsa_t = create_dsa_signature(2048, msg)
    ec_sig, ec_t = create_ecdsa_signature(msg)

    print("Performance (signature length, signing time):")
    print(f"  RSA   {len(rsa_sig)} bytes   {rsa_t*1000:.2f} ms")
    print(f"  DSA   {len(dsa_sig)} bytes   {dsa_t*1000:.2f} ms")
    print(f"  ECDSA {len(ec_sig)} bytes   {ec_t*1000:.2f} ms")

    print("\nComputational cost (operations of the dominant step, O(L) / O(L*n^2)):")
    for name, L, op in [("RSA-2048  (m^d mod n)", 2048, "mod-mult of 2048-bit numbers"),
                        ("DSA-2048  (g^k mod p)",  256, "mod-mult of 2048-bit numbers"),
                        ("ECDSA-384 (k*G)",        384, "point-op over a 384-bit field")]:
        print(f"  {name}: L={L} bits  ~{binary_method_ops(L)} {op}")
