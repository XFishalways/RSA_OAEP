from rsa_oaep.rsa import generate_keypair
from rsa_oaep.rsa_oaep import rsa_oaep_encrypt, rsa_oaep_decrypt
import hashlib
import time


def basic_correctness_test():
    messages = [
        b"hello",
        b"RSA-OAEP test message",
        b"",
        b"\x00\x01\x02\x03\xff",
    ]

    pub, priv = generate_keypair(bits=1024)
    print("Generated 1024-bit key.")

    for m in messages:
        c = rsa_oaep_encrypt(m, pub, hash_func=hashlib.sha3_256)
        r = rsa_oaep_decrypt(c, priv, hash_func=hashlib.sha3_256)
        print(f"Message: {m!r}")
        print(f"Recovered: {r!r}")
        assert r == m, "decryption mismatch!"
        print("OK\n")


def performance_test(bits: int = 1024, rounds: int = 50):
    print(f"\n=== Performance test ({bits}-bit RSA, {rounds} rounds) ===")
    t0 = time.time()
    pub, priv = generate_keypair(bits=bits)
    t1 = time.time()
    print(f"Key generation took {t1 - t0:.3f} s")

    m = b"performance test message"
    c_list = []

    t2 = time.time()
    for _ in range(rounds):
        c = rsa_oaep_encrypt(m, pub, hash_func=hashlib.sha3_256)
        c_list.append(c)
    t3 = time.time()
    print(f"{rounds} encryptions took {t3 - t2:.3f} s "
          f"(avg {(t3 - t2) / rounds:.4f} s each)")

    t4 = time.time()
    for c in c_list:
        _ = rsa_oaep_decrypt(c, priv, hash_func=hashlib.sha3_256)
    t5 = time.time()
    print(f"{rounds} decryptions took {t5 - t4:.3f} s "
          f"(avg {(t5 - t4) / rounds:.4f} s each)")


if __name__ == "__main__":
    basic_correctness_test()
    performance_test(bits=1024, rounds=20)

