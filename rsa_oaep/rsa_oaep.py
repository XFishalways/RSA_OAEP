import hashlib

from .rsa import RSAPublicKey, RSAPrivateKey, rsa_encrypt_int, rsa_decrypt_int
from .oaep import oaep_encode, oaep_decode, HashConstructor
from .utils import i2osp, os2ip, modulus_byte_length


def rsa_oaep_encrypt(
    message: bytes,
    pub: RSAPublicKey,
    hash_func: HashConstructor = hashlib.sha3_256,
    label: bytes = b"",
) -> bytes:
    """
    RSA-OAEP encryption(high-level)
    Args:
        message: Plaintext message
        pub: RSA public key
        hash_func: Hash constructor
        label: Optional OAEP label L
    Returns:
        Ciphertext as bytes of length k
    """
    k = modulus_byte_length(pub.n)
    em = oaep_encode(message, k, hash_func=hash_func, label=label)
    m_int = os2ip(em)
    c_int = rsa_encrypt_int(m_int, pub)
    ciphertext = i2osp(c_int, k)
    return ciphertext


def rsa_oaep_decrypt(
    ciphertext: bytes,
    priv: RSAPrivateKey,
    hash_func: HashConstructor = hashlib.sha3_256,
    label: bytes = b"",
) -> bytes:
    """
    RSA-OAEP decryption(high-level)
    Args:
        ciphertext: Ciphertext as bytes
        priv: RSA private key
        hash_func: Hash constructor used during encryption
        label: OAEP label L
    Returns:
        Plaintext message M
    Raises:
        ValueError
    """
    k = modulus_byte_length(priv.n)
    if len(ciphertext) != k:
        raise ValueError("ciphertext has incorrect length")

    c_int = os2ip(ciphertext)
    m_int = rsa_decrypt_int(c_int, priv)
    em = i2osp(m_int, k)
    message = oaep_decode(em, k, hash_func=hash_func, label=label)
    return message
