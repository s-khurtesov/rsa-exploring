import rsa


def p1(n: int, ea: int, eb: int, db: int, debug=False) -> dict:
    # 1
    N = eb * db - 1

    f = 0
    s = int(N)
    while not s & 1:
        s //= 2
        f += 1

    if debug:
        print('N = 2^{} * {}'.format(f, s))

    t = -1
    while True:
        # 2
        a = int.from_bytes(rsa.get_random_bytes(256), 'big') % n
        b = pow(a, s, n)

        # 3
        bl_pred = b
        for l in range(1, n):
            bl = pow(bl_pred, 2, n)
            if bl == 1:
                assert (pow(b, 2 ** l, n) == 1)
                assert (pow(b, 2 ** (l - 1), n) == bl_pred)
                t = int(bl_pred)
                break
            bl_pred = int(bl)
        if t != n - 1 and t != 1:
            break
    if debug:
        print('t = {}'.format(t))

    # 4
    p, q = rsa.GCD(t + 1, n), rsa.GCD(t - 1, n)
    if debug:
        print('p = {}, q = {}'.format(p, q))

    # 5
    phi_n = rsa.phi(p, q)
    da = rsa.inverse(ea, phi_n)
    if debug:
        print('da = {}'.format(da))

    # 6
    return {
        'p': p, 'q': q,
        'da': da
    }


if __name__ == '__main__':
    # П-1. Случай общего модуля

    a_key_pair = rsa.generate_key_pair(
        rsa.PREDEFINED_PQE['p'],
        rsa.PREDEFINED_PQE['q'],
        rsa.PREDEFINED_PQE['e'],
    )
    b_key_pair = rsa.generate_key_pair(
        a_key_pair['secret']['p'],
        a_key_pair['secret']['q'],
        def_e=None,
        e_bits=2 * 8
    )

    print("b_key_pair['public']", b_key_pair['public'])
    print("b_key_pair['private']", b_key_pair['private'])
    print("a_key_pair['public']", a_key_pair['public'])

    p1_result = p1(
        a_key_pair['public']['n'],
        a_key_pair['public']['e'],
        b_key_pair['public']['e'],
        b_key_pair['private']['d'],
        debug=False
    )
    print(p1_result)

    assert (
            (p1_result['p'] == a_key_pair['secret']['p'] and p1_result['q'] == a_key_pair['secret']['q']) or
            (p1_result['p'] == a_key_pair['secret']['q'] and p1_result['q'] == a_key_pair['secret']['p'])
    )
    assert (p1_result['da'] == a_key_pair['private']['d'])

    print("\n\na_key_pair['private']", a_key_pair['private'])

