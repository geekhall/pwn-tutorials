#!/usr/bin/env python                                                       
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = 'debug'
p = process('./naughty')
elf = ELF('./naughty')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

