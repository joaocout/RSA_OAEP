import hashlib
import base64

import rsa


# max size of RSA_OAEP is: n.bit_length() / 8 - 2 * hlen - 2 = 126 (in this case)
MESSAGE = 'ola oi, segcomp, brasilia'


def main():
    # PARTE 1: GERAÇÃO DE CHAVES E CIFRA
    keys = rsa.generate_keys()
    public = keys['public']
    private = keys['private']

    print('Public key: \n', public, '\n')
    print('Private key: \n', private, '\n')

    enc = rsa.encrypt_with_oaep(MESSAGE.encode(), public)
    print('Message after encryption: \n', enc, '\n')

    dec = rsa.decrypt_with_oaep(enc, private).decode()
    print('Message after decryption: \n', dec, '\n')

    # PARTE 2: ASSINATURA
    # https://cryptobook.nakov.com/digital-signatures/rsa-signatures
    hash = hashlib.sha3_512(MESSAGE.encode()).digest()
    signature = rsa.encrypt_with_oaep(hash, private)
    b64_signature: bytes = base64.b64encode(signature)
    print('B64 signature: \n', b64_signature)

    # PARTE 3: VERIFICAÇÃO
    _signature: bytes = base64.b64decode(b64_signature)
    _hash = rsa.decrypt_with_oaep(_signature, public)

    if (_hash == hashlib.sha3_512(MESSAGE.encode()).digest()):
        print('\nSignature verified\n')
    else:
        raise Exception('Invalid signature')


main()
