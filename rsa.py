from base64 import b64decode, b64encode
from typing import Tuple

from Crypto.Util.number import getPrime, GCD, inverse
from Crypto.Random import get_random_bytes

from math import log2

from Crypto.Hash import SHA3_256

DEBUG = True
PREDEFINED = True

PREDEFINED_PQE = {
    'e': 65537,
    'p': 97993133443977191052236559836104857676495017702294943098555996712165213443082945179300142563377015538162408019041093358531318267483336710926399128837648548469035079352180994027145514967461629810308651010302851777509136325191802639453410138366894069326685012015021771134780312956580600554507246346218030422911,
    'q': 146967632134931519672277065781360862363055040084592632819820959116562831124323530372564741607534672180041943548297264422076279661417095777955667560258243178444836567357395287948040286747542283428085337086366282290234042305840858982640503582085607969443207426861079515207084627928829533439223164413527103299007
}


def phi(p_: int, q_: int) -> int:
    def lcm(a: int, b: int) -> int:
        return abs(a * b) // GCD(a, b)

    return lcm(p_ - 1, q_ - 1)


def generate_key_pair(def_p: int = None, def_q: int = None, def_e: int = None, pq_bits: int = 1024,
                      e_bits: int = None) -> dict:
    def find_e(phi_n_: int) -> int:
        if def_e is not None:
            return def_e

        e_ = int.from_bytes(get_random_bytes(e_bits//8), 'big')
        while GCD(e_, phi_n_) != 1:
            e_ = int.from_bytes(get_random_bytes(e_bits//8), 'big')
        return e_

    p = getPrime(pq_bits) if def_p is None else def_p
    q = getPrime(pq_bits) if def_q is None else def_q
    n = p * q

    if e_bits is None:
        e_bits = int(log2(n)) + 1

    phi_n = phi(p, q)

    e = find_e(phi_n)

    d = inverse(e, phi_n)

    if not (e * d) % phi_n == 1:
        print('(e * d) % phi_n =', (e * d) % phi_n)
        raise ValueError('E and D generated incorrectly')

    if not pow(pow(123456789, e, n), d, n) == 123456789:
        raise Exception('D(E(m)) != m')

    if not pow(pow(123456789, d, n), e, n) == 123456789:
        raise Exception('E(D(m)) != m')

    return {
        'public': {
            'n': n, 'e': e
        },
        'private': {
            'n': n, 'd': d
        },
        'secret': {
            'p': p, 'q': q
        }
    }


def rsa_process(msg: bytes, n: int, e_or_d: int, n_bytes=None) -> bytes:
    if n_bytes is None:
        n_bytes = int(log2(n)) + 1
        if n_bytes % 8 != 0:
            n_bytes = (n_bytes // 8) + 1
        else:
            n_bytes //= 8

    pad = len(msg) % n_bytes
    if pad:
        msg += b'=' * (n_bytes - pad)

    res = bytes()
    for i in range(0, len(msg), n_bytes):
        m = msg[i:i + n_bytes]

        cipher = pow(int.from_bytes(m, 'big'), e_or_d, n) \
            .to_bytes(n_bytes, 'big')

        # print(int.from_bytes(m, 'big'), '->', int.from_bytes(cipher, 'big'))

        res += cipher
    return res


def rsa_enc(msg: bytes, public_key: dict, n_bytes=None) -> bytes:
    return rsa_process(b64encode(msg), public_key['n'], public_key['e'], n_bytes)


def rsa_dec(msg: bytes, private_key: dict, n_bytes=None) -> bytes:
    return b64decode(rsa_process(msg, private_key['n'], private_key['d'], n_bytes))


def rsa_sign(m: bytes, private_key: dict) -> bytes:
    h_obj = SHA3_256.new()
    h_obj.update(m)
    r = h_obj.digest()
    s = rsa_enc(r, {'n': private_key['n'], 'e': private_key['d']})

    return s


def rsa_check(m: bytes, public_key: dict, s: bytes) -> Tuple[bytes, bytes]:
    t = rsa_dec(s, {'n': public_key['n'], 'd': public_key['e']}).rstrip(bytes(1))

    h_obj = SHA3_256.new()
    h_obj.update(m)
    r = h_obj.digest()

    return r, t


def rsa_test(test_key_pair: dict, show: bool = True) -> None:
    if show:
        print('key pair:', test_key_pair)

    test = bytes('testRsaCipher1234567890', 'utf-8')

    enc_test = rsa_enc(test, test_key_pair['public'])
    dec_test = rsa_dec(enc_test, test_key_pair['private']).rstrip(bytes(1))

    if show:
        print('m      :', test.hex())
        print('E(m)   :', enc_test.hex())
        print('D(E(m)):', dec_test.hex())

    assert (test == dec_test)

    sign = rsa_sign(test, test_key_pair['private'])
    r, t = rsa_check(test, test_key_pair['public'], sign)

    if show:
        print('sign:', sign)
        print('r   :', r)
        print('t   :', t)

    assert (r == t)


if __name__ == "__main__":
    if PREDEFINED:
        key_pair = generate_key_pair(
            def_p=PREDEFINED_PQE['p'],
            def_q=PREDEFINED_PQE['q'],
            def_e=PREDEFINED_PQE['e']
        )
    else:
        key_pair = generate_key_pair(def_e=2 ** 16 + 1)

    if DEBUG:
        rsa_test(key_pair)
