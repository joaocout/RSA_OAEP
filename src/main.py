import rsa


MESSAGE = 'oi olá, seg comp, attackatdawn!'


def main():
    keys = rsa.generate_keys()
    public = keys['public']
    private = keys['private']

    print('public key: \n', public, '\n')
    print('private key: \n', private, '\n')

    _, n = public

    enc = rsa.encrypt(MESSAGE.encode(), public)
    print('message after encryption: \n', enc, '\n')

    received = rsa.decrypt(enc, private).decode()
    print('message after decryption: \n', received, '\n')


main()
