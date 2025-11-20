# RSA–OAEP (Python Implementation)

## 1. Overview

This project provides a complete from-scratch implementation of the RSA–OAEP public-key encryption scheme using SHA3-256.
All cryptographic components are implemented manually using only Python's standard library:

- Miller–Rabin primality testing  
- Random prime generation  
- RSA key generation  
- Modular arithmetic  
- MGF1  
- OAEP encoding and decoding  
- RSA encryption and decryption  

No external cryptographic libraries (e.g., `pycryptodome`) are used.  
All big-integer operations rely solely on Python's built-in arbitrary-precision integers.

---

## 2. Dependencies

The implementation requires Python 3.10.

No third-party libraries are needed. The following standard library modules are used:

- `hashlib` (SHA3-256)
- `secrets` (CSPRNG)
- `time` (benchmark timing)

---

## 3. How to Run

For basic test:

```shell
make test
# or
python3 test.py
```

For experiment in the report:

```shell
make experiments
# or
python3 experiments.py
```