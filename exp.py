
from chinese_remainder_theorem import chinese_remainder_theorem
from gmpy2 import *#iroot, invert, powmod
from Crypto.Util.number import *
from sage.all import *
from pwn import *
from os import system
import binascii

n_list = []
e_list = []
c_list = []
e_3_idx = []
e_5_idx = []

plaintext_dict = {}

prefix = ''

def boardcast_attack(n_c_dict, e):
    m = chinese_remainder_theorem(n_c_dict)
    res = iroot(m, e)
    if res[1] == 1:
        return res[0]
    else:
        return 0

def get_prefix(i):
    return int(hex(prefix)[2:] + hex(i)[2:].rjust(8, '0') + '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' + 16 * '0', 16)

def common_modulus_attack(N, e_1, e_2, c_1, c_2):
    d_1 = invert(e_1, e_2)
    d_2 = (d_1 * e_1 - 1) // e_2
    real_c2 = invert(c_2, N)
    return (powmod(c_1, d_1, N) * powmod(real_c2, d_2, N)) % N

def rsa_decrypt(N, c, d):
    return powmod(c, d, N)

def pollard_rho(N):
    log.info("pollard for: {}".format(N))
    a = 2
    f = a
    while True:
        for n in range(1, 200000):
            f = powmod(f, n, N)
            if is_prime(n):
                d = gcd(f - 1, N)
                if 1 < d < N:
                    return d, N // d
                elif d >= N:
                    f = next_prime(a)
                    break
            else:
                break

if __name__ == '__main__':
    # read data from file
    e_set = set()
    for i in range(21):
        with open("./data/Frame" + str(i)) as f:
            per_data = f.read()
            n_list.append(int(per_data[0:256], 16))
            e_list.append(int(per_data[256:512], 16))
            c_list.append(int(per_data[512:768], 16))
            log.info("Frame {}: n->{} e->{} c->{}".format(i, n_list[i], e_list[i], c_list[i]))
            e_set.add(e_list[i])
            if e_list[i] == 3:
                e_3_idx.append(i)
            if e_list[i] == 5:
                e_5_idx.append(i)
    print(e_set)

    # boardcast attack
    '''
    e_3_msg = ''
    m_a_dict = {}
    for i in e_3_idx:
        m_a_dict[n_list[i]] = c_list[i]
    res_e_3 = boardcast_attack(m_a_dict, 3)
    log.success("res for e == 3: {}".format(res_e_3))
    if res_e_3 != 0:
        msg = res_e_3 & 0xffffffffffffffff
        prefix = res_e_3 ^ msg
        log.success("for e=5, prefix:{}".format(hex(prefix)))
        log.success("for e=5, msg:{}".format(hex(msg)))
        e_3_msg = p64(msg)[::-1].decode()
    '''
    
    e_5_msg = ''
    m_a_dict = {}
    for i in e_5_idx:
        m_a_dict[n_list[i]] = c_list[i]
    res_e_5 = boardcast_attack(m_a_dict, 5)
    log.success("res for e == 5: {}".format(res_e_5))
    if res_e_5 != 0:
        msg = res_e_5 & 0xffffffffffffffff
        prefix = int(hex(res_e_5)[2:18], 16)
        log.success("for e=5, prefix:{}".format(hex(prefix)))
        log.success("for e=5, msg:{}".format(hex(msg)))
        e_5_msg = msg
    
    for i in e_5_idx:
        plaintext_dict[i] = e_5_msg
    
    log.success("msg for frame{}: {}".format(e_5_idx, e_5_msg))
    
    # Coppersmith attack
    for i in e_3_idx:
        PR = PolynomialRing(Zmod(n_list[i]), 'x', names=('x',)); (x,) = PR._first_ngens(1)
        for j in range(21):
            pfx = get_prefix(j)
            f = (pfx + x) ** 3  - c_list[i]
            x_0 = f.small_roots(X = 2  ** 64 , beta = 1 )
            if len(x_0) != 0 :
                log.success("msg for frame{}: {}".format(i, x_0[0]))
                plaintext_dict[i] = x_0[0]
    
    # Common Modulus Attack
    for i in range(21):
        for j in range(i, 21):
            if i != j and n_list[i] == n_list[j] and e_list[i] != e_list[j]:
                res_comm = common_modulus_attack(n_list[i], e_list[i], e_list[j], c_list[i], c_list[j]) & 0xffffffffffffffff
                log.success("msg for frame{}: {}".format((i, j), res_comm))
                plaintext_dict[i] = plaintext_dict[j] = res_comm
    
    # fermat division
    for i in range(21):
        if i not in plaintext_dict:
            p_q = iroot(n_list[i], 2)[0]
            for j in range(20000):
                p_q += 1
                if iroot(p_q**2 - n_list[i], 2)[1] == 1:
                    tmp = iroot(p_q**2 - n_list[i], 2)[0]
                    p = p_q + tmp
                    q = p_q - tmp
                    phi = (p - 1) * (q - 1)
                    d = invert(e_list[i], phi)
                    res_format = rsa_decrypt(n_list[i], c_list[i], d) & 0xffffffffffffffff
                    log.success("msg for frame{}: {}".format(i, res_format))
                    plaintext_dict[i] = res_format
    
    # factor collision
    for i in range(21):
        for j in range(i, 21):
            if i != j:
                p = gcd(n_list[i], n_list[j])
                if 1 < p < n_list[i]:
                    q1 = n_list[i] // p
                    q2 = n_list[j] // p
                    phi_1 = (p - 1) * (q1 - 1)
                    phi_2 = (p - 1) * (q2 - 1)
                    d_1 = invert(e_list[i], phi_1)
                    d_2 = invert(e_list[j], phi_2)
                    res_factor_1 = rsa_decrypt(n_list[i], c_list[i], d_1) & 0xffffffffffffffff
                    res_factor_2 = rsa_decrypt(n_list[j], c_list[j], d_2) & 0xffffffffffffffff
                    if res_factor_1:
                        log.success("msg for frame{}: {}".format(i, res_factor_1))
                    if res_factor_2:
                        log.success("msg for frame{}: {}".format(j, res_factor_2))
    
    p_idx = [i for i in plaintext_dict]
    p_idx.sort()
    final = b''
    for i in p_idx:
        per_p = plaintext_dict[i]
        if isinstance(per_p, mpz):
            per_p = int(per_p.__str__())
            
        log.success("plaintext for frame{} :{}".format(i, bytes.fromhex(hex(per_p)[2:])))
    
    # pollard rho
    for i in range(21):
        if i not in plaintext_dict:
            res = pollard_rho(n_list[i])
            if res != None:
                p, q = res
                phi = (p - 1) * (q - 1)
                d = invert(e_list[i], phi)
                res_pollard = rsa_decrypt(n_list[i], c_list[i], d) & 0xffffffffffffffff
                log.success("msg for frame{}: {}".format(i, res_pollard))
                plaintext_dict[i] = res_pollard
    