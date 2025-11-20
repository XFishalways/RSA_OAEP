from dataclasses import dataclass

from .number_theory import gcd, modinv
from .prime import generate_prime


@dataclass
class RSAPublicKey:
    n: int
    e: int


@dataclass
class RSAPrivateKey:
    n: int
    d: int


def generate_keypair(bits: int = 2048, e: int = 65537) -> tuple[RSAPublicKey, RSAPrivateKey]:
    """
    Generate an RSA key pair
    Args:
        bits: Modulus bit length
        e: Public exponent
    Returns:
        (public_key, private_key)
    """
    if bits < 512:
        raise ValueError("bit length too small")

    p_bits = bits // 2
    q_bits = bits - p_bits

    while True:
        p = generate_prime(p_bits)
        q = generate_prime(q_bits)

        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        if gcd(e, phi) != 1:
            continue

        d = modinv(e, phi)
        break

    pub = RSAPublicKey(n=n, e=e)
    priv = RSAPrivateKey(n=n, d=d)
    return pub, priv


def rsa_encrypt_int(m: int, pub: RSAPublicKey) -> int:
    """
    RSA encryption on integer message
    Args:
        m: Integer in [0, n-1]
        pub: Public key
    Returns:
        c = m^e mod n
    """
    if not (0 <= m < pub.n):
        raise ValueError("message representative out of range")
    return pow(m, pub.e, pub.n)


def rsa_decrypt_int(c: int, priv: RSAPrivateKey) -> int:
    """
    RSA decryption on integer ciphertext
    Args:
        c: Integer in [0, n-1]
        priv: Private key
    Returns:
        m = c^d mod n
    """
    if not (0 <= c < priv.n):
        raise ValueError("ciphertext representative out of range")
    return pow(c, priv.d, priv.n)
