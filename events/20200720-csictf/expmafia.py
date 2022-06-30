from pwn import *
context(log_level='debug')

p = remote('chall.csivit.com', 30721)
maxNum = 700000
richArr=[]

for i in range(1,301):
    print i
    p.sendline("1 " + str(i) + " " + str(maxNum))
    res = p.recvline().replace('\n','')
    if res == 'G':
        richArr.append(i)

richLen = len(richArr)

print "##############################"
print len(richArr)
print richArr
print "##############################"
'''
while richLen > 10:
    maxNum = maxNum + (800000 - maxNum)
    for i in richLen:
        p.sendline("1 " + str(i) + " " + str(maxNum))
        res = p.recvline().replace('\n','')
        if res == 'L':
            richArr.remove(i)
print "##############################"
print len(richArr)
print richArr
print "##############################"

'''

p.interactive()

