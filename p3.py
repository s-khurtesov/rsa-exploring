from typing import Tuple

import rsa
from math import sqrt, log2
from base64 import b64decode, b64encode
import aes
import asn1


def factorize_all(n_: int) -> list:
    n = int(n_)
    factors = list()
    if n % 2 == 0:
        factors.append(2)
        n //= 2
        # print(2)
    d = 3
    sqrt_n = sqrt(n)
    while d < sqrt_n:
        while n % d == 0:
            factors.append(d)
            n //= d
            sqrt_n = sqrt(n)
            # print(d)
            if d < sqrt_n:
                break
        d += 2
    factors.append(n)
    return factors


def gen_vuln_key_pairs(count: int = 5):
    result = list()

    while len(result) < count:
        try:
            try:
                key_pair = rsa.generate_key_pair(pq_bits=16, e_bits=32)
                rsa.rsa_test(key_pair, False)
            except KeyboardInterrupt:
                #             raise
                break
        except:
            #         raise
            continue

        p = key_pair['secret']['p']
        q = key_pair['secret']['q']
        e = key_pair['public']['e']

        phi_n = rsa.phi(p, q)

        factors_all = factorize_all(phi_n)

        for order in factors_all:
            if pow(e, order, phi_n) == 1:
                result.append((order, key_pair))

    return result


def p3(c: int, n: int, e: int, debug: bool = False, max_iters=10 ** 6, exact=False) -> Tuple[int, int]:
    if debug:
        print('c = {}'.format(c))
    ci_pred = int(c)
    e_order = -1
    for order in range(1, max_iters + 1):
        ci = pow(ci_pred, e, n)
        if ci == c:
            e_order = order
            if debug:
                print('order = {}'.format(e_order))
            if not exact:
                break
        ci_pred = int(ci)
    if debug:
        print('m = {}'.format(ci_pred))
    return ci_pred, e_order


def rsa_keyless(msg: bytes, n: int, e: int, max_iters=10 ** 6, n_bytes=None, debug: bool = False) -> Tuple[bytes, int]:
    if n_bytes is None:
        n_bytes = int(log2(n)) + 1
        if n_bytes % 8 != 0:
            n_bytes = (n_bytes // 8) + 1
        else:
            n_bytes //= 8

    pad = len(msg) % n_bytes
    if pad:
        msg += b'=' * (n_bytes - pad)

    # Get order
    attack_iters = 3
    e_order_list = [-1]
    for i in range(0, min(n_bytes * attack_iters, len(msg)), n_bytes):
        m_int = int.from_bytes(msg[i:i + n_bytes], 'big')

        _, order = p3(m_int, n, e, max_iters=max_iters, debug=debug)

        if order > 0:
            e_order_list.append(order)

    e_order = max(e_order_list)
    if debug:
        print('final order = {}'.format(e_order))
    assert (e_order > 0)

    res = bytes()
    for i in range(0, len(msg), n_bytes):
        m_int = int.from_bytes(msg[i:i + n_bytes], 'big')

        cipher_int, _ = p3(m_int, n, e, max_iters=e_order - 1, exact=True, debug=debug)

        res += cipher_int.to_bytes(n_bytes, 'big')
    return b64decode(res), e_order


def aes_decrypt_file(in_name: str, out_name: str, key: bytes, offset: int = 0) -> None:
    with open(in_name, 'rb') as fin:
        cipher = fin.read()[offset:]
    dec = aes.aes_dec(cipher, key)
    with open(out_name, 'wb') as fout:
        fout.write(dec)


def cs_keyless_decrypt(
        in_name: str, out_name: str,
        asn1_json_name: str
) -> Tuple[dict, bytes, int]:
    # Decode ASN1 cipher file
    _, offset = asn1.asn1_to_json(in_name, asn1_json_name)

    cipher_asn: dict = asn1.parse_cipher_file(asn1_json_name)

    print('cipher_asn:\n', cipher_asn)

    rsa_public_key: dict = cipher_asn['asym_public_key']
    enc_aes_sym_key: bytes = asn1.int_to_bytes(cipher_asn['asym_cipher'])

    # Decrypt file with key from ASN1
    aes_sym_key, order = rsa_keyless(
        enc_aes_sym_key, rsa_public_key['n'], rsa_public_key['e']
    )

    aes_decrypt_file(in_name, out_name, aes_sym_key, offset)

    return rsa_public_key, aes_sym_key, order


if __name__ == '__main__':
    # П-3. Случай специальных открытых показателей

    # vuln_key_pairs = [
    #     (9, {'public': {'n': 2454706559, 'e': 2654597089}, 'private': {'n': 2454706559, 'd': 15163885}, 'secret': {'p': 43093, 'q': 56963}}),
    #     (320, {'public': {'n': 3117231701, 'e': 3267033989}, 'private': {'n': 3117231701, 'd': 22501709}, 'secret': {'p': 54401, 'q': 57301}}),
    #     (384, {'public': {'n': 2162977793, 'e': 3772771849}, 'private': {'n': 2162977793, 'd': 7396921}, 'secret': {'p': 43777, 'q': 49409}}),
    #     (192, {'public': {'n': 2127702113, 'e': 15110843}, 'private': {'n': 2127702113, 'd': 12295667}, 'secret': {'p': 34273, 'q': 62081}}),
    #     (880, {'public': {'n': 2725218169, 'e': 2908331861}, 'private': {'n': 2725218169, 'd': 79552541}, 'secret': {'p': 49369, 'q': 55201}}),
    #     (87136, {'public': {'n': 3074270473, 'e': 2410281229}, 'private': {'n': 3074270473, 'd': 13236229}, 'secret': {'p': 47041, 'q': 65353}}),
    #     (2459136, {'public': {'n': 3718335781, 'e': 4011413723}, 'private': {'n': 3718335781, 'd': 49503059}, 'secret': {'p': 57637, 'q': 64513}}),
    # ] \
        # + [(0, myrsa.generate_key_pair(
        #     # myrsa.PREDEFINED_PQE['p'],
        #     # myrsa.PREDEFINED_PQE['q'],
        #     # myrsa.PREDEFINED_PQE['e'],
        #     pq_bits=16, e_bits=32
        # ))]

    vuln_key_pairs = gen_vuln_key_pairs(2)

    for orig_order, key_pair in vuln_key_pairs:
        m = 1337
        print(end='m:{} -> '.format(m))

        n = key_pair['public']['n']
        e = key_pair['public']['e']

        # Encrypt
        c = pow(m, e, n)
        print(end='c:{} -> '.format(c))
        assert (pow(c, key_pair['private']['d'], n) == m)

        # Keyless decryption
        m_dec, order = p3(c, n, e, debug=False)

        # Check
        print('m_dec:{}, orig_order:{}, order:{}'.format(m_dec, orig_order, order))
        assert (m == m_dec)

    # --- FILE ---
    # test_keypair = {
    #     'public': {'n': 3117231701, 'e': 3267033989},
    #     'private': {'n': 3117231701, 'd': 22501709},
    #     'secret': {'p': 54401, 'q': 57301}
    # }
    orig_order = 320
    in_path = 'p3-enc-balloon.jpg.bin'
    out_path = 'p3-dec-balloon.jpg'
    out_asn1_path = 'p3-dec-balloon.jpg.asn1.json'

    file_rsa_pubkey, file_aes_key, order = cs_keyless_decrypt(in_path, out_path, out_asn1_path)
    print('out_path:{}\nfile_rsa_pubkey:{}\nfile_aes_key:{}\norig_order:{}, order:{}'.format(
        out_path, file_rsa_pubkey, asn1.bytes_to_int(file_aes_key), orig_order, order
    ))
