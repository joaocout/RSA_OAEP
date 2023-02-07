import math
import oaep


def rsa_encrypt(message: bytes, public_key: tuple[int, int]) -> bytes:
    # with oaep

    e, n = public_key

    # m^e (mod n)
    c = pow(int.from_bytes(message, 'big'), e, n)

    return c.to_bytes(math.ceil(c.bit_length() / 8), 'big')


def rsa_decrypt(cryptogram: bytes, private_key: tuple[int, int]) -> bytes:
    # with oaep

    d, n = private_key

    # c^d (mod n)
    m = pow(int.from_bytes(cryptogram, 'big'), d, n)

    m = m.to_bytes(math.ceil(m.bit_length() / 8), 'big')

    return m
