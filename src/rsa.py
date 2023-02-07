import math
import random
import oaep


def generate_random_number(length: int = 1024) -> int:
    while True:
        n = random.getrandbits(length)

        # return the number only if it has the specified length
        if len(bin(n)[2:]) == length:
            return n


def primality_test(n: int, k: int = 128) -> bool:
    if n == 2 or n == 3:
        return True

    if n <= 1 or n % 2 == 0:
        return False

    # https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    s = 0
    r = n - 1

    while r & 1 == 0:
        s += 1
        r //= 2

    d = (n - 1) // pow(2, s)

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)

        y = 0
        for __ in range(s):
            y = pow(x, 2, n)
            if y == 1 and x != 1 and x != n - 1:
                return False
            x = y

        if y != 1:
            return False
    return True


def generate_random_prime_number(length: int = 1024) -> int:
    while True:
        n = generate_random_number(length)
        if primality_test(n):
            return n


def choose_e(phi: int) -> int:
    e = 65537  # 2^16 + 1

    while math.gcd(e, phi) != 1:
        e = random.randrange(e, phi)

    return e


def find_d(e: int, phi: int) -> int:
    # multiplicative inverse
    return pow(e, -1, phi)


def generate_keys() -> dict[str, tuple[int, int]]:
    p = generate_random_prime_number()
    q = generate_random_prime_number()

    n = p*q
    # euler totient
    phi = (p-1) * (q-1)

    e = choose_e(phi)
    d = find_d(e, phi)

    return {
        "public": (e, n),
        "private": (d, n)
    }


def encrypt(message: bytes, public_key: tuple[int, int]) -> bytes:
    # using oaep
    e, n = public_key
    k = math.ceil(n.bit_length() / 8)

    encoded_message = oaep.encode(message, k)

    # m^e (mod n)
    c = pow(int.from_bytes(encoded_message, 'big'), e, n)

    return c.to_bytes(k, 'big')


def decrypt(cryptogram: bytes, private_key: tuple[int, int]) -> bytes:
    # using oaep
    d, n = private_key
    k = math.ceil(n.bit_length() / 8)

    # c^d (mod n)
    m = pow(int.from_bytes(cryptogram, 'big'), d, n)

    m = m.to_bytes(k, 'big')

    decoded_message = oaep.decode(m, k)

    return decoded_message
