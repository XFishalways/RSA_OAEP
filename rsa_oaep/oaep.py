from typing import Callable
import hashlib

from .utils import i2osp, random_bytes


HashConstructor = Callable[[bytes], "hashlib.sha3_256"]


def mgf1(seed: bytes, mask_len: int, hash_func: HashConstructor = hashlib.sha3_256) -> bytes:
    """
    Mask Generation Function
    Args:
        seed: Input seed
        mask_len: Desired mask length in bytes
        hash_func: Hash constructor
    Returns:
        Pseudorandom mask of length
    """
    hlen = hash_func(b"").digest_size
    if mask_len > (1 << 32) * hlen:
        raise ValueError("mask too long")

    output = bytearray()
    counter = 0
    while len(output) < mask_len:
        c = i2osp(counter, 4)
        digest = hash_func(seed + c).digest()
        output.extend(digest)
        counter += 1
    return bytes(output[:mask_len])


def oaep_encode(
    message: bytes,
    k: int,
    hash_func: HashConstructor = hashlib.sha3_256,
    label: bytes = b"",
) -> bytes:
    """
    OAEP encoding
    Args:
        message: Message M
        k: Length of RSA modulus in bytes
        hash_func: Hash constructor
        label: Optional label L
    Returns:
        Encoded message EM of length k bytes
    Raises:
        ValueError
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
    return em


def oaep_decode(
    em: bytes,
    k: int,
    hash_func: HashConstructor = hashlib.sha3_256,
    label: bytes = b"",
) -> bytes:
    """
    OAEP decoding
    Args:
        em: Encoded message
        k: RSA modulus length in bytes
        hash_func: Hash constructor used in encoding
        label: Optional label L
    Returns:
        Decoded message M
    Raises:
        ValueError
    """
    hlen = hash_func(b"").digest_size

    if len(em) != k:
        raise ValueError("encoded message has incorrect length")

    if em[0] != 0x00:
        raise ValueError("decryption error: leading byte is not 0x00")

    masked_seed = em[1:1 + hlen]
    masked_db = em[1 + hlen:]

    seed_mask = mgf1(masked_db, hlen, hash_func=hash_func)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))

    db_mask = mgf1(seed, k - hlen - 1, hash_func=hash_func)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))

    lhash_prime = db[:hlen]
    rest = db[hlen:]

    expected_lhash = hash_func(label).digest()
    if lhash_prime != expected_lhash:
        raise ValueError("decryption error: lHash mismatch")

    # Find separator
    try:
        idx = rest.index(b"\x01")
    except ValueError:
        raise ValueError("decryption error: 0x01 not found")

    ps = rest[:idx]
    if any(b != 0x00 for b in ps):
        raise ValueError("decryption error: non-zero padding in PS")

    message = rest[idx + 1:]
    return message
