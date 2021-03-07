import json
from math import log2
from typing import Tuple

DEBUG = True
VERBOSE = False

SEQUENCE = 0x30
SET = 0x31
INTEGER = 0x02
UTF_STRING = 0x0C
OCTET_STRING = 0x04

RSA_ID = '00 01'
AES_ID = '10 81'
RSA_SHA256_ID = '00 40'


def verbose(*args, **kwargs):
    if VERBOSE:
        print(args, kwargs)


def bytes_to_int(bs: bytes) -> int:
    return int.from_bytes(bs, 'big')


def int_to_bytes(num: int, signed: bool = False) -> bytes:
    size = int(log2(num) // 8 + 1)
    if signed and num >> (size * 8 - 1) & 1:
        size += 1
    return num.to_bytes(size, 'big')


def get_size(size: int) -> bytes:
    if size > 128:
        size_k = int(log2(size) // 8 + 1)
        size_bytes = bytes([128 + size_k]) + size.to_bytes(size_k, 'big')
    else:
        size_bytes = bytes([size])
    return size_bytes


def sequence(sub_set: bytes) -> bytes:
    size_bytes = get_size(len(sub_set))
    return bytes([SEQUENCE]) + size_bytes + sub_set


def set_(sub_set: bytes) -> bytes:
    size_bytes = get_size(len(sub_set))
    return bytes([SET]) + size_bytes + sub_set


def integer(num: int) -> bytes:
    bs = int_to_bytes(num, signed=False)
    size_bytes = get_size(len(bs))
    return bytes([INTEGER]) + size_bytes + bs


def utf_string(s: str) -> bytes:
    bs = bytes(s, 'utf-8')
    size_bytes = get_size(len(bs))
    return bytes([UTF_STRING]) + size_bytes + bs


def octet_string(hex_str: str) -> bytes:
    bs = bytes.fromhex(hex_str)
    size_bytes = get_size(len(bs))
    return bytes([OCTET_STRING]) + size_bytes + bs


def build_cipher_file(
        path: str,
        asym_alg: str, asym_label: str, asym_public_key: dict, asym_cipher: int,
        sym_alg: str, sym_len: int
) -> None:
    asn1_data = \
        sequence(
            set_(
                sequence(
                    octet_string(asym_alg) +
                    utf_string(asym_label) +
                    sequence(
                        integer(asym_public_key['n']) +
                        integer(asym_public_key['e'])
                    ) +
                    sequence(bytes()) +
                    sequence(
                        integer(asym_cipher)
                    )
                )
            ) +
            sequence(
                octet_string(sym_alg) +
                integer(sym_len)
            )
        )

    with open(path, 'wb') as fout:
        fout.write(asn1_data)


def build_sign_file(
        path: str,
        alg: str, label: str, public_key: dict, sign_num: int
) -> None:
    asn1_data = \
        sequence(
            set_(
                sequence(
                    octet_string(alg) +
                    utf_string(label) +
                    sequence(
                        integer(public_key['n']) +
                        integer(public_key['e'])
                    ) +
                    sequence(bytes()) +
                    sequence(
                        integer(sign_num)
                    )
                )
            ) +
            sequence(bytes())
        )

    with open(path, 'wb') as fout:
        fout.write(asn1_data)


def parse(asn: bytes, cur_tag: int = None, cur_size: int = None, cur: int = 0, depth: int = 0):
    cur_i = int(cur)

    res = list()
    while cur_size is None or cur_i < cur + cur_size:
        size = asn[cur_i + 1]
        size_k = 0
        if (size >> 7) & 1:
            size_k = size & 0x7F
            size = bytes_to_int(asn[cur_i + 2:cur_i + 2 + size_k])

        verbose('{1:3} {2:3}: {0}'.format('  ' * depth, cur_i, size), end='')

        if asn[cur_i] == SEQUENCE:
            verbose('SEQUENCE {')
            sub_res = parse(asn, SEQUENCE, size, cur_i + 2 + size_k, depth + 1)
            res.append({'SEQUENCE': sub_res})
            verbose(' ' * 9 + '  ' * depth + '}')
        elif asn[cur_i] == SET:
            verbose('SET {')
            sub_res = parse(asn, SET, size, cur_i + 2 + size_k, depth + 1)
            res.append({'SET': sub_res})
            verbose(' ' * 9 + '  ' * depth + '}')
        elif asn[cur_i] == INTEGER:
            verbose('INTEGER ', end='\n' + ' ' * 9 + '  ' * (depth + 1))
            bs = asn[cur_i + 2 + size_k:cur_i + 2 + size_k + size]
            res.append({'INTEGER': int.from_bytes(bs, 'big')})
            verbose(bs.hex())
        elif asn[cur_i] == UTF_STRING:
            verbose('UTF_STRING ', end='\n' + ' ' * 9 + '  ' * (depth + 1))
            bs = asn[cur_i + 2 + size_k:cur_i + 2 + size_k + size]
            res.append({'UTF_STRING': bs.decode('utf-8')})
            verbose(bs.hex())
        elif asn[cur_i] == OCTET_STRING:
            verbose('OCTET_STRING ', end='\n' + ' ' * 9 + '  ' * (depth + 1))
            bs = asn[cur_i + 2 + size_k:cur_i + 2 + size_k + size]
            res.append({'OCTET_STRING': ' '.join('{:02x}'.format(x) for x in bs)})
            verbose(bs.hex())
        else:
            verbose(hex(asn[cur_i]))
            raise ValueError('Unknown tag')

        cur_i = cur_i + 2 + size_k + size

        if cur_size is None:
            return res, cur_i

    return res


def asn1_to_json(in_name: str, out_name: str) -> Tuple[dict, int]:
    with open(in_name, 'rb') as fin:
        asn = fin.read()

    verbose(len(asn), asn.hex())

    parsed, offset = parse(asn)

    parsed = parsed[0]

    parsed_js = json.loads(str(parsed).replace('\'', '"'))
    parsed_js_pretty = json.dumps(parsed_js, indent=2)

    with open(out_name, 'wb') as fout:
        fout.write(bytes(parsed_js_pretty, 'utf-8'))

    return parsed, offset


def read_parsed_file(in_name: str):
    with open(in_name, 'rb') as fin:
        parsed = json.load(fin)

    return parsed


def parse_cipher_file(in_name: str) -> dict:
    cipher_asn1_raw = read_parsed_file(in_name)

    res = {
        'asym_alg': cipher_asn1_raw['SEQUENCE'][0]['SET'][0]['SEQUENCE'][0]['OCTET_STRING'],
        'asym_label': cipher_asn1_raw['SEQUENCE'][0]['SET'][0]['SEQUENCE'][1]['UTF_STRING'],
        'asym_public_key': {
            'n': cipher_asn1_raw['SEQUENCE'][0]['SET'][0]['SEQUENCE'][2]['SEQUENCE'][0]['INTEGER'],
            'e': cipher_asn1_raw['SEQUENCE'][0]['SET'][0]['SEQUENCE'][2]['SEQUENCE'][1]['INTEGER']
        },
        'asym_cipher': cipher_asn1_raw['SEQUENCE'][0]['SET'][0]['SEQUENCE'][4]['SEQUENCE'][0]['INTEGER'],
        'sym_alg': cipher_asn1_raw['SEQUENCE'][1]['SEQUENCE'][0]['OCTET_STRING'],
        'sym_len': cipher_asn1_raw['SEQUENCE'][1]['SEQUENCE'][1]['INTEGER']
    }

    return res


def parse_sign_file(in_name: str) -> dict:
    sign_asn1_raw = read_parsed_file(in_name)

    res = {
        'alg': sign_asn1_raw['SEQUENCE'][0]['SET'][0]['SEQUENCE'][0]['OCTET_STRING'],
        'label': sign_asn1_raw['SEQUENCE'][0]['SET'][0]['SEQUENCE'][1]['UTF_STRING'],
        'public_key': {
            'n': sign_asn1_raw['SEQUENCE'][0]['SET'][0]['SEQUENCE'][2]['SEQUENCE'][0]['INTEGER'],
            'e': sign_asn1_raw['SEQUENCE'][0]['SET'][0]['SEQUENCE'][2]['SEQUENCE'][1]['INTEGER']
        },
        'sign': sign_asn1_raw['SEQUENCE'][0]['SET'][0]['SEQUENCE'][4]['SEQUENCE'][0]['INTEGER']
    }

    return res


if __name__ == "__main__":
    if DEBUG:
        import rsa
        import aes

        # Get keys
        key_pair = rsa.generate_key_pair(
            def_p=rsa.PREDEFINED_PQE['p'],
            def_q=rsa.PREDEFINED_PQE['q'],
            def_e=rsa.PREDEFINED_PQE['e']
        )
        aes_key = aes.PREDEFINED_AES_KEY

        # Encrypt symmetric key
        enc_aes_key = rsa.rsa_enc(aes_key, key_pair['public'])

        # Get sign
        data = b'testing asn1 structure'
        sign = rsa.rsa_sign(data, key_pair['private'])

        # Write ASN1 files
        build_cipher_file('./asn1-cipher.bin', RSA_ID, 'test', key_pair['public'], bytes_to_int(enc_aes_key), AES_ID, 100)
        build_sign_file('./asn1-sign.bin', RSA_SHA256_ID, 'testSign', key_pair['public'], bytes_to_int(sign))

        # Decode ASN1 files
        _ = asn1_to_json('./asn1-cipher.bin', './asn1-cipher.json')
        _ = asn1_to_json('./asn1-sign.bin', './asn1-sign.json')

        cipher_asn = parse_cipher_file('./asn1-cipher.json')
        sign_asn = parse_sign_file('./asn1-sign.json')

        print(cipher_asn)
        print(sign_asn)
