from typing import Tuple

import rsa
import aes
import asn1


def encrypt_file(in_name: str, out_name: str, key: bytes) -> int:
    with open(in_name, 'rb') as fin:
        plaintext = fin.read()
    enc = aes.aes_enc(plaintext, key)
    with open(out_name, 'wb') as fout:
        fout.write(enc)
    return len(enc)


def decrypt_file(in_name: str, out_name: str, key: bytes) -> None:
    with open(in_name, 'rb') as fin:
        cipher = fin.read()
    dec = aes.aes_dec(cipher, key)
    with open(out_name, 'wb') as fout:
        fout.write(dec)


def cs_init() -> Tuple[dict, bytes]:
    new_rsa_keypair: dict = rsa.generate_key_pair(
        def_p=rsa.PREDEFINED_PQE['p'],
        def_q=rsa.PREDEFINED_PQE['q'],
        def_e=rsa.PREDEFINED_PQE['e']
    )
    new_aes_key: bytes = aes.PREDEFINED_AES_KEY

    return new_rsa_keypair, new_aes_key


def cs_encrypt(
        in_name: str, out_name: str, asn1_name: str,
        rsa_public_key: dict, aes_sym_key: bytes
) -> None:
    # Encrypt test file
    enc_file_len: int = encrypt_file(in_name, out_name, aes_sym_key)

    # Encrypt symmetric key
    enc_aes_key: bytes = rsa.rsa_enc(aes_sym_key, rsa_public_key)

    # Write ASN1 cipher file
    asn1.build_cipher_file(
        asn1_name,
        asn1.RSA_ID, 'test', rsa_public_key, asn1.bytes_to_int(enc_aes_key),
        asn1.AES_ID, enc_file_len
    )


def cs_decrypt(
        in_name: str, out_name: str,
        asn1_name: str, asn1_json_name: str,
        rsa_private_key: dict
) -> Tuple[dict, bytes]:
    # Decode ASN1 cipher file
    _ = asn1.asn1_to_json(asn1_name, asn1_json_name)

    cipher_asn: dict = asn1.parse_cipher_file(asn1_json_name)

    print('cipher_asn:\n', cipher_asn)

    rsa_public_key: dict = cipher_asn['asym_public_key']
    enc_aes_sym_key: bytes = asn1.int_to_bytes(cipher_asn['asym_cipher'])

    # Decrypt file with key from ASN1
    aes_sym_key: bytes = rsa.rsa_dec(enc_aes_sym_key, rsa_private_key)

    decrypt_file(in_name, out_name, aes_sym_key)

    return rsa_public_key, aes_sym_key


def cs_encryption_check(
        in_name: str, out_name: str,
        asn1_rsa_public_key: dict, asn1_aes_sym_key: bytes,
        rsa_public_key: dict, aes_sym_key: bytes
) -> bool:
    assert (asn1_rsa_public_key == rsa_public_key)
    assert (asn1_aes_sym_key == aes_sym_key)

    with open(out_name, 'rb') as f_dec, open(in_name, 'rb') as f_orig:
        is_dec_equal_orig = f_dec.read() == f_orig.read()

    return is_dec_equal_orig


def cs_sign_create(
        in_name: str, asn1_name: str, rsa_private_key: dict, rsa_public_key: dict
) -> int:
    # Get sign
    with open(in_name, 'rb') as f_test:
        data = f_test.read()

    new_sign: int = asn1.bytes_to_int(rsa.rsa_sign(data, rsa_private_key))

    # Write ASN1 sign files
    asn1.build_sign_file(
        asn1_name,
        asn1.RSA_SHA256_ID, 'testSign', rsa_public_key, new_sign
    )

    return new_sign


def cs_sign_check(
        in_name: str, asn1_name: str, asn1_json_name: str,
        orig_rsa_public_key: dict = None, orig_sign: int = None
) -> bool:
    # Decode ASN1 sign file
    _ = asn1.asn1_to_json(asn1_name, asn1_json_name)

    sign_asn: dict = asn1.parse_sign_file(asn1_json_name)

    print('sign_asn:\n', sign_asn)

    asn1_rsa_pub_key: dict = sign_asn['public_key']
    asn1_sign: int = sign_asn['sign']

    if orig_rsa_public_key is not None:
        assert (asn1_rsa_pub_key == orig_rsa_public_key)

    if orig_sign is not None:
        assert (asn1_sign == orig_sign)

    with open(in_name, 'rb') as f_test:
        r, t = rsa.rsa_check(
            f_test.read(),
            asn1_rsa_pub_key, asn1.int_to_bytes(asn1_sign)
        )

    return r == t


if __name__ == "__main__":
    FILE = 'balloon.jpg'
    FILE_ENC = 'enc-' + FILE
    FILE_ENC_ASN = FILE_ENC + '.asn1'
    FILE_ENC_ASN_JSON = FILE_ENC_ASN + '.json'
    FILE_DEC = 'dec-' + FILE
    FILE_DEC_ASN = FILE_DEC + '.asn1'
    FILE_DEC_ASN_JSON = FILE_DEC_ASN + '.json'
    FILE_SIGN_ASN = 'sign-' + FILE + '.asn1'
    FILE_SIGN_ASN_JSON = 'sign-' + FILE + '.json'

    # Get keys
    rsa_key_pair, aes_key = cs_init()

    # --- ENCRYPTION ---
    cs_encrypt(
        FILE, FILE_ENC, FILE_ENC_ASN,
        rsa_key_pair['public'], aes_key
    )

    dec_rsa_public_key, dec_aes_key = cs_decrypt(
        FILE_ENC, FILE_DEC,
        FILE_ENC_ASN, FILE_DEC_ASN_JSON,
        rsa_key_pair['private']
    )

    assert cs_encryption_check(
        FILE, FILE_DEC,
        dec_rsa_public_key, dec_aes_key,
        rsa_key_pair['public'], aes_key
    )

    # --- SIGN ---
    sign = cs_sign_create(
        FILE, FILE_SIGN_ASN,
        rsa_key_pair['private'], rsa_key_pair['public']
    )

    assert cs_sign_check(
        FILE, FILE_SIGN_ASN, FILE_SIGN_ASN_JSON,
        rsa_key_pair['public'], sign
    )
