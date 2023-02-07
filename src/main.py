import rsa_keygen
import rsa_enc_dec
import oaep
import math


def main():
    keys = rsa_keygen.generate_keys()
    public = keys['public']
    private = keys['private']

    _, n = public

    message = 'oi ola, seg comp, attackatdawn!'

    a = oaep.oaep_encode(message.encode(), math.ceil(n.bit_length() / 8))

    print(a)

    b = oaep.oaep_decode(a, math.ceil(n.bit_length() / 8))

    print(b)


main()
