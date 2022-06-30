#!/usr/bin/env python
# -*- coding:utf-8 -*-

from pwn import *

elf = ELF('./el_primo')
p= process('./el_primo')

p.recvuntil('What\'s my hard counter?\n')


