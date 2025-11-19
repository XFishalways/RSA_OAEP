from __future__ import annotations


def gcd(a: int, b: int) -> int:
    """
    Compute gcd of a and b
    """
    while b != 0:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Extended Euclidean algorithm
    Returns:
         (g, x, y) with g = gcd(a, b) and ax + by = g
    """
    if b == 0:
        return a, 1, 0
    else:
        g, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return g, x, y


def modinv(a: int, m: int) -> int:
    """
    Modular inverse: find x such that (a * x) % m == 1
    Raises:
        ValueError: if gcd(a, m) != 1
    """
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m
