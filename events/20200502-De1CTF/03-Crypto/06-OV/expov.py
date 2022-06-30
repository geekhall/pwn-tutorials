from pwn import *
context.log_level ="debug"
#sh=remote('134.175.225.42', 8848)
sh=remote('134.175.220.99', 8848)
sh.recvuntil("sha256(XXXX+")
crypto = sh.recv(16)
log.debug(crypto)
sh.recvuntil("== ")
cipher = sh.recv(64)
log.debug(cipher)

#skr = sh.recv(10).decode("hex")
#print "crypto = " + crypto + "  key = " + skr.encode("hex")
def bomb():
    for i in range(48,122):
        for j in range(48,122):
            for k in range(48,122):
            	for l in range(48,122):
                    key = hashlib.sha256(chr(i)+chr(j)+chr(k)+chr(l)+crypto).hexdigest()
                    if key == cipher:
                        return chr(i)+chr(j)+chr(k)+chr(l)

sha = bomb()
#print sha
sh.recvuntil("Give me XXXX:")
sh.sendline(sha)
sh.recvline()
sh.sendline("king")
sh.recvall()
sh.interactive()
