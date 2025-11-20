"""
Experiments for RSA-OAEP implementation:

1. Probabilistic test
2. OAEP internal tracing
3. Performance analysis
4. Integrity & robustness tests
"""

import time
import hashlib

from rsa_oaep.rsa import generate_keypair
from rsa_oaep.rsa_oaep import rsa_oaep_encrypt, rsa_oaep_decrypt
from rsa_oaep.oaep import mgf1, HashConstructor
from rsa_oaep.utils import random_bytes, modulus_byte_length, i2osp, os2ip
from rsa_oaep.rsa import rsa_encrypt_int, rsa_decrypt_int


def experiment_probabilistic_encryption() -> None:
    """
    Experiment 1: Probabilistic test
    """
    print("=== Experiment 1: Probabilistic Test ===")
    pub, priv = generate_keypair(bits=1024)
    message = b"Hello World"

    c1 = rsa_oaep_encrypt(message, pub, hash_func=hashlib.sha3_256)
    c2 = rsa_oaep_encrypt(message, pub, hash_func=hashlib.sha3_256)

    print(f"Plaintext: {message!r}")
    print(f"Ciphertext 1 (hex): {c1.hex()}")
    print(f"Ciphertext 2 (hex): {c2.hex()}")
    print("Equal?", c1 == c2)
    print("Note: Due to the random seed inside OAEP, "
          "the two ciphertexts should be completely different even for the same message.\n")


def oaep_encode_trace(
    message: bytes,
    k: int,
    hash_func: HashConstructor = hashlib.sha3_256,
    label: bytes = b"",
) -> bytes:
    """
    Experiment 2: OAEP Internal Tracing
    intermediate variables: seed, DB, dbMask, maskedDB, seedMask, maskedSeed
    """
    hlen = hash_func(b"").digest_size
    mlen = len(message)

    if mlen > k - 2 * hlen - 2:
        raise ValueError("message too long for OAEP")

    lhash = hash_func(label).digest()
    ps_len = k - mlen - 2 * hlen - 2
    ps = b"\x00" * ps_len

    db = lhash + ps + b"\x01" + message
    if len(db) != k - hlen - 1:
        raise ValueError("internal error: DB length mismatch")

    seed = random_bytes(hlen)
    db_mask = mgf1(seed, k - hlen - 1, hash_func=hash_func)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))

    seed_mask = mgf1(masked_db, hlen, hash_func=hash_func)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))

    em = b"\x00" + masked_seed + masked_db
    if len(em) != k:
        raise ValueError("internal error: EM length mismatch")

    # output
    print("lHash      :", lhash.hex())
    print("PS length  :", ps_len)
    print("DB         :", db.hex())
    print("Seed       :", seed.hex())
    print("dbMask     :", db_mask.hex())
    print("maskedDB   :", masked_db.hex())
    print("seedMask   :", seed_mask.hex())
    print("maskedSeed :", masked_seed.hex())
    print("EM         :", em.hex())
    print()

    return em


def experiment_oaep_tracing() -> None:
    print("=== Experiment 2: OAEP Internal Tracing ===")
    pub, _ = generate_keypair(bits=1024)
    message = b"Trace OAEP!"

    k = modulus_byte_length(pub.n)
    print(f"Modulus size: {k} bytes")
    print(f"Message: {message!r}\n")

    em = oaep_encode_trace(message, k, hash_func=hashlib.sha3_256, label=b"")

    print("The values above correspond to the OAEP structure")


def experiment_performance() -> None:
    """
    Experiment 3: Performance Test
    """
    print("=== Experiment 3: Performance Analysis ===")
    key_sizes = [1024, 2048]
    rounds = 50
    hash_func = hashlib.sha3_256

    print(f"{'Key Size (bits)':>14} | {'KeyGen Time (s)':>14} | "
          f"{'Enc Time (ms)':>12} | {'Dec Time (ms)':>12}")
    print("-" * 60)

    for bits in key_sizes:
        # Key generation time
        t0 = time.time()
        pub, priv = generate_keypair(bits=bits)
        t1 = time.time()
        keygen_time = t1 - t0

        message = b"Performance test message"
        k = modulus_byte_length(pub.n)

        # Encryption time
        t2 = time.time()
        ciphertexts = []
        for _ in range(rounds):
            c = rsa_oaep_encrypt(message, pub, hash_func=hash_func)
            ciphertexts.append(c)
        t3 = time.time()
        enc_time_total = t3 - t2

        # Decryption time
        t4 = time.time()
        for c in ciphertexts:
            _ = rsa_oaep_decrypt(c, priv, hash_func=hash_func)
        t5 = time.time()
        dec_time_total = t5 - t4

        enc_ms = (enc_time_total / rounds) * 1000
        dec_ms = (dec_time_total / rounds) * 1000

        print(f"{bits:14d} | {keygen_time:14.3f} | "
              f"{enc_ms:12.3f} | {dec_ms:12.3f}")

    print("\nKey generation time grows more quickly with key size, "
          "and decryption is significantly slower than encryption, "
          "because of the large private exponent.\n")


def experiment_integrity_and_robustness() -> None:
    """
    Experiment 4: Integrity & Robustness Tests
    """
    print("=== Experiment 4: Integrity & Robustness Tests ===")
    pub, priv = generate_keypair(bits=1024)
    message = b"All-or-nothing property test"

    # Part 1: Corrupted ciphertext
    print("\n--- Part 1: Corrupted Ciphertext ---")
    c = rsa_oaep_encrypt(message, pub, hash_func=hashlib.sha3_256)
    corrupted = bytearray(c)
    corrupted[-1] ^= 0x01

    try:
        _ = rsa_oaep_decrypt(bytes(corrupted), priv, hash_func=hashlib.sha3_256)
        print("Failure: decryption succeeded on corrupted ciphertext")
    except ValueError as e:
        print("Decryption failed on corrupted ciphertext as expected.")
        print("Caught exception:", repr(e))

    # Part 2: Mismatched label
    print("\n--- Part 2: Mismatched OAEP label ---")
    label_enc = b"confidential"
    label_dec = b"public"

    c_label = rsa_oaep_encrypt(message, pub,
                               hash_func=hashlib.sha3_256,
                               label=label_enc)

    try:
        _ = rsa_oaep_decrypt(c_label, priv,
                             hash_func=hashlib.sha3_256,
                             label=label_dec)
        print("Failure: decryption succeeded with different labels")
    except ValueError as e:
        print("Decryption failed with mismatched label as expected.")
        print("Caught exception:", repr(e))

    print("\nThese experiments show that:\n"
          "1. Any modification to the ciphertext causes decryption to fail.\n"
          "2. The OAEP label is cryptographically bound into the encoding.\n")



def main() -> None:
    experiment_probabilistic_encryption()
    experiment_oaep_tracing()
    experiment_performance()
    experiment_integrity_and_robustness()


if __name__ == "__main__":
    main()
