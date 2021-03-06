from base64 import b64decode, b64encode

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random.random import getrandbits

DEBUG = True
PREDEFINED = True
PREDEFINED_AES_KEY = (22809166456208946160975605292332392846622853394559301883250916203138556237466).to_bytes(32, 'big')


def generate_aes_key() -> bytes:
    return getrandbits(32 * 8).to_bytes(32, 'big')


def aes_enc(message_: bytes, key: bytes) -> bytes:
    def aes_pad(s):
        pad = len(s) % AES.block_size
        if pad:
            pad = AES.block_size - pad
        return s + b"=" * pad

    message = b64encode(message_)

    message = aes_pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)


def aes_dec(ciphertext: bytes, key: bytes) -> bytes:
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return b64decode(plaintext)


def aes_test(key: bytes) -> None:
    print('key:', int.from_bytes(key, 'big'))

    test = bytes('testAesCipher1234567890', 'utf-8')

    enc_test = aes_enc(test, key)
    dec_test = aes_dec(enc_test, key)  # .rstrip(bytes(1))

    print('m      :', test.hex())
    print('E(m)   :', enc_test.hex())
    print('D(E(m)):', dec_test.hex())

    assert (test == dec_test)


if __name__ == "__main__":
    if PREDEFINED:
        aes_key = PREDEFINED_AES_KEY
    else:
        aes_key = generate_aes_key()

    if DEBUG:
        aes_test(aes_key)
