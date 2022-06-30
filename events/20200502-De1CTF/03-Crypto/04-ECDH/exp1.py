from pwn import *
context.log_level ="debug"
sh=remote('134.175.225.42', 8848)
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
'''
The params are: 
q: 100173830297345234246296808618734115432031228596757431606170574500462062623677
a: 34797263276731929172113534470189285565338055361167847976642146658712494152186
b: 39258950039257324692361857404792305546106163510884954845070423459288379905976
P: (82031236592532820689585715102128084141757606384165265204422508645702672267722,33439355059297433276103816374972293139178479876025851884027868838522796014258)
Q: (36123485446873294494445400065291011647076014121829695561727951095677166093627,88856627934023117108395852812431270959097367321607194577121275762669328028254)
Give me your key:
X:

next?

q=100173830297345234246296808618734115432031228596757431606170574500462062623677
a=34797263276731929172113534470189285565338055361167847976642146658712494152186
b=39258950039257324692361857404792305546106163510884954845070423459288379905976
P=(82031236592532820689585715102128084141757606384165265204422508645702672267722,33439355059297433276103816374972293139178479876025851884027868838522796014258)
sh.recvuntil("Q: ")
Q=sh.recvline()[1,-1]
sh.recvuntil("X:\n")
payload=''
sh.sendline(payload)
'''
sh.interactive()