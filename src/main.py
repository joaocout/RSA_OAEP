import hashlib
import base64

import rsa


# max size of RSA_OAEP is: n.bit_length() / 8 - 2 * hlen - 2 = 126 (in this case)
MESSAGE = 'ola oi, segcomp, brasilia ola oi, segcomp, brasiliaola oi, segcomp, brasiliaola oi, segcomp, brasiliaola oi, segcomp, brasiliaola oi, segcomp, brasiliaola oi, segcomp, brasiliaola oi, segcomp, brasiliaola oi, segcomp, brasiliaola oi, segcomp, brasiliaola oi, segcomp, brasiliaola oi, segcomp, brasiliaola oi, segcomp, brasiliaola oi, segcomp, brasiliaola oi, segcomp, brasiliaola oi, segcomp, brasiliaola oi, segcomp, brasilia'
MESSAGE_BYTES = MESSAGE.encode()
BLOCK_SIZE = 100
RESULT_BLOCK_SIZE = 256


def main():
    # PART 1: KEY GENERATION AND CIPHERING/DECIPHERING
    keys = rsa.generate_keys()
    public = keys['public']
    private = keys['private']

    print('Public key: \n', public, '\n')
    print('Private key: \n', private, '\n')

    enc: bytes = b''
    # dividing message into chunks so it's possible to work arround the size limitation
    for i in range(0, len(MESSAGE_BYTES), BLOCK_SIZE):
        enc += rsa.encrypt_with_oaep(MESSAGE_BYTES[i:i + BLOCK_SIZE], public)
        print(len(enc))

    print('Message after encryption: \n', enc, '\n')

    dec: str = ''
    for i in range(0, len(enc), RESULT_BLOCK_SIZE):
        dec += rsa.decrypt_with_oaep(enc[i: i +
                                         RESULT_BLOCK_SIZE], private).decode()

    print('Message after decryption: \n', dec, '\n')

    # PART 2: SIGNING
    # https://cryptobook.nakov.com/digital-signatures/rsa-signatures
    hash = hashlib.sha3_512(MESSAGE.encode()).digest()
    signature = rsa.encrypt_with_oaep(hash, private)
    b64_signature: bytes = base64.b64encode(signature)
    print('B64 signature: \n', b64_signature)

    # PART 3: VERIFICATION
    _signature: bytes = base64.b64decode(b64_signature)
    _hash = rsa.decrypt_with_oaep(_signature, public)

    if (_hash == hashlib.sha3_512(MESSAGE.encode()).digest()):
        print('\nSignature verified\n')
    else:
        raise Exception('Invalid signature')


main()
