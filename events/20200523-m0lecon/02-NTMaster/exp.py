from pwn import *
import gmpy2
from gmpy2 import mpz, mpq, mpfr, mpc
context(os="linux", arch="amd64",log_level = "debug")

p = remote('challs.m0lecon.it', 10000)
for i in range(10):
    p.recvuntil('N = ')
    N = mpz(p.recvuntil('\n'))
    a, b = int(N) - 1, 1
    p.sendline(str(a) + " " + str(b))

p.interactive()





