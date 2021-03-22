import rsa
from decimal import localcontext, Decimal
from math import log2
from typing import Tuple


def gen_vuln_key_pair(p: int, q: int, debug: bool = False, thres_coef: int = 10 ** 100) -> Tuple[dict, int]:
    def gen_e_for_short_d(p_: int, q_: int, thres: int = None, show=False) -> int:
        if thres is None:
            with localcontext() as ctx:
                ctx.prec = 500
                exp = Decimal(1 / 4)
                n_025 = ctx.power(p_ * q_, exp)
                thres = int((1 / 3) * float(n_025)) + 1

        n = p * q
        phi_n = rsa.phi(p, q)
        e_res = -1
        for d in range(thres, 4, -1):
            e = rsa.inverse(d, phi_n)

            if not rsa.GCD(e, phi_n) == 1:
                continue

            if not (e * d) % phi_n == 1:
                continue

            if not pow(pow(123456789, e, n), d, n) == 123456789:
                continue

            if not pow(pow(123456789, d, n), e, n) == 123456789:
                continue

            e_res = e
            if show:
                print('e, d = {}, {}'.format(e, d))
            else:
                break
        return e_res

    with localcontext() as ctx:
        ctx.prec = 500
        exp = Decimal(1 / 4)
        n_025 = ctx.power(p * q, exp)
        threshold = int((1 / 3) * float(n_025)) + 1
    if debug:
        print('threshold = {}'.format(threshold))

    E_FOR_SHORT_D = gen_e_for_short_d(
        p, q, threshold // thres_coef
    )

    if debug:
        print('E_FOR_SHORT_D = {}'.format(E_FOR_SHORT_D))

    key_pair = rsa.generate_key_pair(
        p, q, E_FOR_SHORT_D,
    )

    assert (key_pair['private']['d'] < threshold)

    return key_pair, threshold


def p2(n: int, e: int, debug: bool = False, threshold: int = None):
    def continued_fraction(a: int, b: int) -> list:
        seq = []
        q = a // b
        r = a % b
        seq.append(q)

        while r != 0:
            a, b = b, r
            q = a // b
            r = a % b
            seq.append(q)

        return seq

    def convergents(a: list) -> dict:
        p = [1, 0]
        q = [0, 1]

        for i in range(1, len(a)):
            pi = a[i]*p[i-1+1] + p[i-2+1]
            qi = a[i]*q[i-1+1] + q[i-2+1]

            p.append(pi)
            q.append(qi)

        return {
            'P': p[1:],
            'Q': q[1:]
        }

    # 1
    seq = continued_fraction(e, n)
    l = len(seq) - 1

    if debug:
        print(l, seq[:5])
    if l > int(log2(n)):
        print('WARNING: len(seq) > log2(n): {} > {}', l, int(log2(n)))

    # 2
    conv = convergents(seq)
    Q = conv['Q']
    m = 123456789

    d = -1
    for i in range(1, l + 1):
        if debug and (i < 6 or i > l - 5):
            print('Q[{}] = {}'.format(i, Q[i]))
        if threshold is not None and Q[i] >= threshold:
            raise ValueError('ERROR: Q[{}] >= threshold'.format(i))
        m_check = pow(pow(m, e, n), Q[i], n)
        if m == m_check:
            d = Q[i]
            if debug:
                print('i = {}'.format(i))
            break
    if debug:
        print(d)
    assert (d > 0)

    # 3

    return d


if __name__ == '__main__':
    # П-2. Случай малого закрытого показателя. Атака Винера
    key_pair, _ = gen_vuln_key_pair(rsa.PREDEFINED_PQE['p'], rsa.PREDEFINED_PQE['q'])

    d = p2(key_pair['public']['n'], key_pair['public']['e'], False)

    print('public: {}\nprivate: {}\nFound d: {}'.format(key_pair['public'], key_pair['private'], d))

    assert (d == key_pair['private']['d'])

    # lv_p, lv_q = 145995953620764359296583445726290260474683223119245396347509799923879018828143650789086226642164151553272364899832097583260318532989720216600503488493046437937991456692608917813969698181157006625609321037637243078032404434016543809403327956754205728584122406641612544335093619479079323981288499521596863599457, 106374519174535285332055653948700932924763768824721787527399196361048432850086801905106303891834352175381349010988030889638281020909763825658219943990543796377067129586834863641039821408878419332848514910202674734713733899968825621566859427174122755920113230539693738796350473567117440599620619708853203140023
    #
    # for i in range(10 ** 10, 10 ** 150, 10 ** 5):
    #     lv_key_pair, threshold = gen_vuln_key_pair(lv_p, lv_q, debug=False, thres_coef=i)
    #
    #     try:
    #         lv_d = p2(lv_key_pair['public']['n'], lv_key_pair['public']['e'], debug=False, threshold=threshold)
    #     except ValueError:
    #         lv_d = -1
    #
    #     if lv_d > 0:
    #         print(lv_key_pair)
    #
    # assert (lv_d == lv_key_pair['private']['d'])
