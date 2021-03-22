from multiprocessing.pool import Pool
from multiprocessing import TimeoutError

import rsa
from math import log2
import numpy as np
import p1, p2, p3


def primesfrom2to(n):
    # https://stackoverflow.com/questions/2068372/fastest-way-to-list-all-primes-below-n-in-python/3035188#3035188
    """ Input n>=6, Returns a array of primes, 2 <= p < n """
    sieve = np.ones(n//3 + (n%6==2), dtype=np.bool)
    sieve[0] = False
    for i in range(int(n**0.5)//3+1):
        if sieve[i]:
            k=3*i+1|1
            sieve[      ((k*k)//3)      ::2*k] = False
            sieve[(k*k+4*k-2*k*(i&1))//3::2*k] = False
    return np.r_[2,3,((3*np.nonzero(sieve)[0]+1)|1)]


PRIMES_FROM_2_TO_1E8 = primesfrom2to(10 ** 8)


def factorize_short(n_: int, primes: list = PRIMES_FROM_2_TO_1E8, debug: bool = False) -> list:
    n = int(n_)
    factors = list()
    for d in primes:
        while n % d == 0:
            factors.append(int(d))
            n //= d
            if debug:
                print('factor: {}'.format(d))
            if n <= d:
                break
    if n < primes[-1]:
        factors.append(int(n))
        if debug:
            print('factor: {}'.format(n))
    if debug:
        print('done: factors')
    return factors


def try_gen_strong_key_pair(def_p: int = None, def_q: int = None, def_e: int = None, pq_bits: int = 1024,
                            e_bits: int = None, min_d_bits: int = None, debug: bool = False) -> dict:
    def find_uniq_pq(bits: int):
        return rsa.getPrime(pq_bits)

    def find_e(phi_n_: int, e_bits_: int, factors_short_: list) -> int:
        if def_e is not None:
            return def_e

        e_ = -1
        while True:
            e_ = int.from_bytes(rsa.get_random_bytes(e_bits_ // 8), 'big')
            while rsa.GCD(e_, phi_n_) != 1:
                e_ = int.from_bytes(rsa.get_random_bytes(e_bits_ // 8), 'big')

            for order in factors_short_:
                if pow(e_, order, phi_n_) == 1:
                    e_ = -1

            if e_ > 0:
                break
            if debug:
                print('Bad \'e\'')

        return e_

    def find_d(e_: int, phi_n_: int, min_d_bits_: int) -> int:
        d_ = rsa.inverse(e_, phi_n_)
        d_bits = int(log2(d_))
        if d_bits < min_d_bits_:
            return -1
        return d_

    # П-1. Число 'n' должно быть уникальным для каждого пользователя
    p = find_uniq_pq(pq_bits) if def_p is None else def_p
    q = find_uniq_pq(pq_bits) if def_q is None else def_q
    n = p * q

    if e_bits is None:
        e_bits = int(log2(n)) + 1

    if min_d_bits is None:
        min_d_bits = int(e_bits * 0.9)

    phi_n = rsa.phi(p, q)

    factors_short = list(set(factorize_short(phi_n, debug=debug)))

    while True:
        # П-3. Открытый показатель 'e' должен быть достаточно большим
        # .... и иметь большой порядок в группе (Z/nZ)*
        e = find_e(phi_n, e_bits, factors_short)

        # П-2. Закрытый показатель 'd' должен быть достаточно большим
        # .... для устойчивости к атаке Винера
        d = find_d(e, phi_n, min_d_bits)
        if d > 0:
            break
        if debug:
            print('Bad \'d\'')

    if not (e * d) % phi_n == 1:
        print('(e * d) % phi_n =', (e * d) % phi_n)
        raise ValueError('E and D generated incorrectly')

    if not pow(pow(123456789, e, n), d, n) == 123456789:
        raise Exception('D(E(m)) != m')

    if not pow(pow(123456789, d, n), e, n) == 123456789:
        raise Exception('E(D(m)) != m')

    new_kp = {
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

    try:
        rsa.rsa_test(new_kp, show=False)
    except Exception as test_e:
        raise Exception('Final test failed: {}'.format(str(test_e)))

    return new_kp


def gen_strong_key_pair(**kwargs):
    new_key_pair = dict()
    while True:
        try:
            try:
                new_key_pair = try_gen_strong_key_pair(*kwargs)
            except KeyboardInterrupt as ki:
                print(str(ki))
                break
        except Exception as gen_e:
            print('Generation failed: {}'.format(str(gen_e)))
            continue
        break
    return new_key_pair


def p2_wrapper(*args, **kwargs):
    try:
        return p2.p2(*args, **kwargs)
    except Exception as p2_e:
        print('p2: Exception {}'.format(str(p2_e)))
    return None


if __name__ == '__main__':
    test_p = None
    timeout = 10

    if test_p is None:
        # Strong keys
        key_pair = gen_strong_key_pair()
        a_key_pair = gen_strong_key_pair()
    elif test_p == 1:
        # p1 vulnerable keys
        key_pair = rsa.generate_key_pair(
            rsa.PREDEFINED_PQE['p'],
            rsa.PREDEFINED_PQE['q'],
            rsa.PREDEFINED_PQE['e'],
        )
        a_key_pair = rsa.generate_key_pair(
            key_pair['secret']['p'],
            key_pair['secret']['q'],
            def_e=None,
            e_bits=2 * 8
        )
    elif test_p == 2:
        # p2 vulnerable keys
        key_pair, _ = p2.gen_vuln_key_pair(rsa.PREDEFINED_PQE['p'], rsa.PREDEFINED_PQE['q'])
        a_key_pair, _ = p2.gen_vuln_key_pair(rsa.PREDEFINED_PQE['p'], rsa.PREDEFINED_PQE['q'])
    elif test_p == 3:
        # p3 vulnerable keys
        tmp = p3.gen_vuln_key_pairs(2)
        key_pair, a_key_pair = tmp[0][1], tmp[1][1]
    else:
        raise ValueError('test_p')

    print(key_pair)

    # П-1. Случай общего модуля
    # ----------------------------
    with Pool(processes=1) as pool:
        p1_success = False
        p1_proc = pool.apply_async(p1.p1, (
            a_key_pair['public']['n'],
            a_key_pair['public']['e'],
            key_pair['public']['e'],
            key_pair['private']['d'],
            False
        ))
        try:
            p1_result = p1_proc.get(timeout=timeout)
        except TimeoutError:
            print('p1: TimeoutError')
        else:
            p1_success = (
                    (p1_result['p'] == a_key_pair['secret']['p'] and p1_result['q'] == a_key_pair['secret']['q']) or
                    (p1_result['p'] == a_key_pair['secret']['q'] and p1_result['q'] == a_key_pair['secret']['p'])
            )
            p1_success = p1_success and (p1_result['da'] == a_key_pair['private']['d'])
        print('p1_success: {}'.format(p1_success))

    # П-2. Случай малого закрытого показателя. Атака Винера
    # -----------------------------------------------------
    with Pool(processes=1) as pool:
        p2_success = False
        p2_proc = pool.apply_async(p2_wrapper, (key_pair['public']['n'], key_pair['public']['e']))
        try:
            d = p2_proc.get(timeout=timeout)
        except TimeoutError:
            print('p2: TimeoutError')
        else:
            p2_success = (d == key_pair['private']['d'])
        print('p2_success: {}'.format(p2_success))

    # П-3. Случай специальных открытых показателей
    # --------------------------------------------
    m = 1337
    print(end='m:{} -> '.format(m))

    n = key_pair['public']['n']
    e = key_pair['public']['e']

    # Encrypt
    c = pow(m, e, n)
    print(end='c:{} -> '.format(c))
    assert (pow(c, key_pair['private']['d'], n) == m)

    # Keyless decryption
    with Pool(processes=1) as pool:
        p3_success = False
        p3_proc = pool.apply_async(p3.p3, (c, n, e, False))
        try:
            m_dec = p3_proc.get(timeout=timeout)
        except TimeoutError:
            print('p3: TimeoutError')
        else:
            # Check
            print('m_dec:{}'.format(m_dec, ))
            p3_success = (m == m_dec)
        print('p3_success: {}'.format(p3_success))
