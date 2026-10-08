from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
from cpu_measure import Measure
import time
from typing import Callable


def _measure_signing(sign: Callable[[], bytes]) -> tuple[bytes, float, int]:
    measure = Measure()
    cpu_start = time.process_time()
    with measure:
        signature = sign()
    cpu_time = time.process_time() - cpu_start
    return signature, cpu_time, measure.cycles


def create_rsa_signature(exp, key_size, msg) -> tuple[bytes, float, int]:
   private_key = rsa.generate_private_key(exp, key_size)
   cpu_times = 0
   total_tsc_ticks = 0
   
   for i in range(100):
      signature, cpu_time, cycles = _measure_signing(
          lambda: private_key.sign(
              data=msg,
              padding=padding.PSS(
                  mgf=padding.MGF1(SHA256()),
                  salt_length=padding.PSS.MAX_LENGTH),
              algorithm=SHA256()))
      cpu_times += cpu_time
      total_tsc_ticks += cycles
       
   return signature, cpu_times / 100, total_tsc_ticks / 100

 
def create_dsa_signature(key_size, msg) -> tuple[bytes, float, int]:
    private_key = dsa.generate_private_key(key_size)
    cpu_times = 0
    total_tsc_ticks = 0
    
    for i in range(100):
      signature, cpu_time, cycles = _measure_signing(
          lambda: private_key.sign(
              data=msg,
              algorithm=SHA256()))
      cpu_times += cpu_time
      total_tsc_ticks += cycles
    
    return signature, cpu_times / 100, total_tsc_ticks / 100

def create_ecdsa_signature(msg) -> tuple[bytes, float, int]:
   private_key = ec.generate_private_key(ec.SECP224R1())
   cpu_times = 0
   total_tsc_ticks = 0
   
   for i in range(100):
      signature, cpu_time, cycles = _measure_signing(
          lambda: private_key.sign(
              msg,
              ec.ECDSA(SHA256())))
      cpu_times += cpu_time
      total_tsc_ticks += cycles
    
   return signature, cpu_times / 100, total_tsc_ticks / 100


if __name__ == "__main__":
    msg = b"Hello, I am a message. You are not"
    
    
    rsa_signature, rsa_time, rsa_cycles = create_rsa_signature(65537, 2048, msg)
    dsa_signature, dsa_time, dsa_cycles = create_dsa_signature(2048, msg)
    ecdsa_signature, ecdsa_time, ecdsa_cycles = create_ecdsa_signature(msg)
    
    print(f"RSA signature length: {len(rsa_signature)}\t Average CPU time: {rsa_time}\t Average TSC ticks: {rsa_cycles}")
    print(f"DSA signature length: {len(dsa_signature)}\t Average CPU time: {dsa_time}\t Average TSC ticks: {dsa_cycles}")
    print(f"ECDSA signature length: {len(ecdsa_signature)}\t Average CPU time: {ecdsa_time}\t Average TSC ticks: {ecdsa_cycles}")
