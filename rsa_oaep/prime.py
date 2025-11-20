import secrets

from .number_theory import gcd


def _random_odd_integer(bits: int) -> int:
    """
    Generate a random odd integer with exact bit length
    Args:
        bits: Length
    Returns:
        Random odd integer
    """
    if bits < 2:
        raise ValueError("bits must be >= 2")
    x = secrets.randbits(bits)

    x |= (1 << (bits - 1))
    x |= 1

    return x


def _decompose_n_minus_one(n: int) -> tuple[int, int]:
    """
    Write n-1 as 2^s * d with d odd
    Returns:
        (s, d)
    """
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    return s, d


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """
    Miller–Rabin primality test
    Args:
        n: Integer being tested
        rounds: Number of random bases
    Returns:
        True if n is a probable prime
    """
    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False

    s, d = _decompose_n_minus_one(n)

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int, rounds: int = 40) -> int:
    """
    Generate a probable prime with the given bit length
    Args:
        bits: Length
        rounds: Rounds
    Returns:
        prime integer
    """
    if bits < 2:
        raise ValueError("bits must be >= 2")

    while True:
        candidate = _random_odd_integer(bits)
        if is_probable_prime(candidate, rounds=rounds):
            return candidate
