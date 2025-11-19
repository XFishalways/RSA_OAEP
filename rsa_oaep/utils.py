import secrets


def i2osp(x: int, x_len: int) -> bytes:
    """
    Integer-to-Octet-String primitive
    Args:
        x: Non-negative integer to convert.
        x_len: Intended length of the resulting byte string
    Raises:
        ValueError: if x is negative or too large
    """
    if x < 0:
        raise ValueError("x must be non-negative")
    if x >= 256 ** x_len:
        raise ValueError("integer too large for the given length")
    return x.to_bytes(x_len, byteorder="big")


def os2ip(x: bytes) -> int:
    """
    Octet-String-to-Integer primitive
    Args:
        x: Byte string to convert
    Returns:
        Corresponding non-negative integer
    """
    return int.from_bytes(x, byteorder="big")


def random_bytes(length: int) -> bytes:
    """
    Generate cryptographically strong random bytes
    Args:
        length: Number of bytes
    Returns:
        Random bytes of given length
    """
    if length < 0:
        raise ValueError("length must be non-negative")
    return secrets.token_bytes(length)


def modulus_byte_length(n: int) -> int:
    """
    Compute the byte length of an RSA modulus n
    Args:
        n: RSA modulus
    Returns:
        Minimal k such that 256^k > n
    """
    if n <= 0:
        raise ValueError("modulus must be positive")
    bits = n.bit_length()
    return (bits + 7) // 8
