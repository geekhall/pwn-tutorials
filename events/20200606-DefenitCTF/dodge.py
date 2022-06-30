from pwn import *

context(log_level='debug')

p=remote('dodge.ctf.defenit.kr',1357)

line = p.recvline()
pos=line.find('hexdigest')
start=pos+len('hexdigest()="')
val=line[start:-2]
#print(val)

for i in range(32,126):
    for j in range(32,126):
        for k in range(32,126):
            user_input=chr(i)+chr(j)+chr(k)
            if hashlib.md5(user_input).hexdigest() == val:
                print user_input
                p.sendline(user_input)
p.interactive()

