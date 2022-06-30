from pwn import *
context(log_level="debug")


def revF(a1):
    v3 = 1
    for i in range(2,a1+1):
        v3 = v3 * i
    return v3

def revC(a1, a2):
    v2 = revF(a1)
    v3 = revF(a2)
    return v2 / (revF(a1 - a2) * v3)


p= remote('chall.csivit.com', 30808)
line=p.recvline().replace('\n','')
print line
line = int(line)
for i in range(line+1):
    ans = revC(line, i)
    p.sendline(str(ans))

p.interactive()

