from pwn import *
context(log_level='debug')

p=remote('minesweeper.ctf.defenit.kr', 3333)
p.recvuntil(':')
p.sendline('a1')

line=p.recvline()
#print line
line=p.recvline()
#print line
line=p.recvline()[5:-1]
print "================================"
print line
print "================================"
p.recvuntil(':')

p.interactive()

