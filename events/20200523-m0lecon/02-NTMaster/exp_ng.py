from pwn import *
import gmpy2
from gmpy2 import mpz, mpq, mpfr, mpc
context(os="linux", arch="amd64",log_level = "debug")



def getans(N):
    ans = ''
    for b in range(1,N):
        for a in range(b, N):
            if gmpy2.gcd(a, b) + gmpy2.lcm(a, b) == N:
                return str(a) + ' ' + str(b)
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





