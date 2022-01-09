import sys
from pwn import *

class NotCoprimeException (Exception):
    pass

# 
def gcd(a, b):
    return gcd(b, a % b) if b else a

# 
def ext_gcd(a, b):
    if b == 0:         
        return 1, 0, a     
    else:         
        x, y, q = ext_gcd(b, a % b)          
        x, y = y, (x - (a // b) * y)         
        return x, y, q

def lcm(a, b):
    return a * b / gcd(a, b)

# get multiplicative inverse modulo
def get_multiplicative_inverse_modulo(a, m):
    x, y, q = ext_gcd(a, m)
    if q != 1:
        raise NotCoprimeException
    return x

def chinese_remainder_theorem(m_a:dict):
    M = 1
    # check whether all the m are coprime
    #log.info("Start checking coprime...")
    for m in m_a:
        M *= m
        for n in m_a:
            if m == n:
                continue
            if gcd(m, n) != 1:
                raise NotCoprimeException

    # get M_i stored in list
    #log.info("Start calculating M_i...")
    i = 1
    M_i_list = []
    for m in m_a:
        per_m_i = M // m
        M_i_list.append(per_m_i)
        #log.info("M_" + str(i) + ": " + str(per_m_i))
        i += 1
    
    # get M_i^-1(t_i) stored in list
    #log.info("Start calculating t_i...")
    i = 1
    M_i_re_list = []
    for M_i, m_i in zip(M_i_list, m_a):
        per_t_i = get_multiplicative_inverse_modulo(M_i, m_i)
        M_i_re_list.append(per_t_i)
        #log.info("t_" + str(i) + ": " + str(per_t_i))
        i += 1
    
    # get x_j stored in list
    #log.info("Start calculating x_j...")
    i = 1
    x_j_list = []
    for M_j, M_re_j, m_j in zip(M_i_list, M_i_re_list, m_a):
        per_x_j = (M_j * M_re_j * m_a[m_j]) % M
        x_j_list.append(per_x_j)
        #log.info("x_" + str(i) + ": " + str(per_t_i))
        i += 1

    # get result
    #log.info("Start calculating the final result...")
    x = 0
    for x_j in x_j_list:
        x += x_j
    x %= M

    return x

if __name__ == '__main__':
    argv = sys.argv
    if len(argv) < 2:
        exit("Usage: python3 chinese_remainder_theorem.py [filename]")

    m_a = {}
    a_m_list = []
    f = open(argv[1])
    l = f.readline()
    while l:
        a_m_list.append(int(l.strip('\n')))
        l = f.readline()
    
    for i in range(len(a_m_list) // 2):
        m_a[a_m_list[i + len(a_m_list) // 2]] = a_m_list[i]
    
    try:
        x = chinese_remainder_theorem(m_a)
    except NotCoprimeException:
        exit("不能直接利用中国剩余定理")
    log.success("Result: " + str(x))

    # for test (input in terminal, luogu P1495)
    '''
    m_a = {}
    num = int(input())
    for i in range(num):
        m, a = input().strip('\n').split(" ")
        m_a[int(m)] = int(a)
    
    x = chinese_remainder_theorem(m_a)
    print(x)
    '''