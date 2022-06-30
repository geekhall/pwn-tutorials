from pwn import *
import gmpy2
from gmpy2 import mpz, mpq, mpfr, mpc
context(os="linux", arch="amd64",log_level = "debug")


# too slow 
def getans1(N):
    ans = ''
    for b in xrange(1,N):
        for a in xrange(b, N):
            if gmpy2.gcd(a, b) + gmpy2.lcm(a, b) == N:
                return a, b

def getans(N):
    ans = ''
    for i in xrange(1,N):
        if gmpy2.is_prime( N - 1):
            return N-1, 1
        else:
            return getans1(N)


N = 3076929430
ans=getans(N)
a,b=getans(N)
print(a)
print(b)
print ans
print(gmpy2.lcm(a, b))
print(gmpy2.gcd(a, b))


#N = 3076929430
print gmpy2.is_prime(N)
print gmpy2.is_prime(N-1)
#ans = getans(N)
#print ans
'''
p = remote('challs.m0lecon.it', 10000)
p.recvuntil('N = ')
N = mpz(p.recvuntil('\n'))
ans=getans(N)
p.sendline(ans)

p.recvuntil('N = ')                                                                         
N = mpz(p.recvuntil('\n'))
ans=getans(N)
p.sendline(ans)

p.recvuntil('N = ')                                                                         
N = mpz(p.recvuntil('\n'))
ans=getans(N)
p.sendline(ans)

p.recvuntil('N = ')                                                                         
N = mpz(p.recvuntil('\n'))
ans=getans(N)
p.sendline(ans)

p.recvuntil('N = ')                                                                         
N = mpz(p.recvuntil('\n'))
ans=getans(N)
p.sendline(ans)

p.recvuntil('N = ')                                                                         
N = mpz(p.recvuntil('\n'))
ans=getans(N)
p.sendline(ans)
'''




