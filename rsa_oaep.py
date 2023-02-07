import os
import math
import hashlib
import rsa_key

H_LEN: int = hashlib.sha3_512().digest_size
LABEL: str = ""


def mgf1(z: bytes, l: int) -> bytes:
    # https://en.wikipedia.org/wiki/Mask_generation_function

    if (l > (H_LEN << 32)):
        raise Exception("Mask too long")

    t: bytes = b''

    counter = 0
    while len(t) < l:
        c = int.to_bytes(counter, 4, 'big')
        t += hashlib.sha3_512(z + c).digest()
        counter += 1

    return t[:l]


def xor(data: bytes, mask: bytes) -> bytes:
    return bytes(a ^ b for (a, b) in zip(data, mask))


def oaep_encode(m: str, k: int) -> bytes:
    # https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
    # sha3_512 used as the hash function

    label_hash = hashlib.sha3_512(LABEL.encode()).digest()

    m_len = len(m.encode())
    ps = b'\x00' * (k - m_len - 2 * H_LEN - 2)

    db = label_hash + ps + b'\x01' + m.encode()

    if len(db) != k - H_LEN - 1:
        raise Exception("Length of data block should be 'k - hlen - 1'")

    seed = os.urandom(H_LEN)

    db_mask = mgf1(seed, k - H_LEN - 1)
    masked_db = xor(db, db_mask)

    seed_mask = mgf1(masked_db, H_LEN)
    masked_seed = xor(seed, seed_mask)

    return b'\x00' + masked_seed + masked_db


def oaep_decode(em: bytes, k: int) -> str:
    # https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
    label_hash = hashlib.sha3_512(LABEL.encode()).digest()

    masked_seed, masked_db = em[1:1 + H_LEN], em[1 + H_LEN:]

    seed_mask = mgf1(masked_db, H_LEN)
    seed = xor(masked_seed, seed_mask)

    db_mask = mgf1(seed, k - H_LEN - 1)
    db = xor(masked_db, db_mask)

    received_label_hash = db[:H_LEN]

    if label_hash != received_label_hash:
        raise Exception("Label hashes are different")

    ps: bytes = b''
    for i in range(H_LEN, len(db)):
        if (db[i] == 1):
            break

        if (db[i] != 0 and db[i] != 1):
            raise Exception('Padding string should be only zeros')

        ps += db[i].to_bytes()

    separator = db[H_LEN + len(ps)]

    if separator != 1:
        raise Exception('Separator should be 0x01')

    m = db[H_LEN + len(ps) + 1:]

    return m.decode()


def main():
    keys = rsa_key.generate_keys()

    # (e, n)
    public_key = keys["public"]

    e, n = public_key

    # (d, n)
    private_key = keys["private"]
    d, _ = private_key

    enc = oaep_encode('hello world, segcomp unb, attack at dawn!',
                      math.ceil(n.bit_length() / 8))

    dec = oaep_decode(enc, math.ceil(n.bit_length() / 8))

    print(dec)


main()
