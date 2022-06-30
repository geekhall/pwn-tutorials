from pwn import *
from hashlib import sha256
import os,random,sys,string
import numpy as np
import gmpy2
# from sage.all import *
import subprocess

def get(m,n):
    l = string.ascii_letters+string.digits    
    for a in l:
        for b in l:
            for c in l:
                for d in l:
                    if sha256(a+b+c+d+m).hexdigest() == n:
                        return a+b+c+d
    return ''
                  
###strSha = get('HwBvjRXk8cTZMpcY','7564c733018b326b3e348ee524eaf7a29186d9de83b77afd44696aad5b50a0a7')

# io = remote('192.168.206.132', 2333)
io = remote('124.156.140.90', 2333)
s = io.recvuntil('XXXX:')
print s
strSha = get(s[12:28],s[33:97])
io.sendline(strSha)
# str = io.recv() 
# print str

s = io.recvuntil('want?')
print (s)

f=open("arg.txt","w")
m = int(s.split('\n')[0].strip()[2:])
print (m)
l = 513
io.sendline(str(l))

f.write(s.split('\n')[0].strip()[2:])
f.write('\n')

# aa=[]
# bb=[]
for i in range(l+1):
    s = io.recvuntil('\n') 
    if i==0:
        continue
    ss = s.split(')=')
    # print ss
    # print ss
    x = int(ss[0][2:])
    # a=[]
    for i in range(l):
        f.write(str(pow (x, i, m)))
        f.write(',')
        # a.append(pow (x, i, m))
    # aa.append(a)
    t = ss[1].strip()
    f.write(t)
    f.write('\n')
    # b = [int(t)]
    # bb.append(b)
    # print x,f
f.close()
# a = matrix(Zmod(m), 0, l)
# a = a.stack(vector(aa[0]))
# a = a.stack(vector(aa[1]))

# b = matrix(Zmod(m), 0, l)
# b=b.stack(vector(bb[0]))
# b=b.stack(vector(bb[1]))

# x=a.solve_right(b)
# print(x[0])
sagepath='testSage.py'
sageresult = subprocess.check_output(["/usr/local/bin/sage -python testSage.py"],shell=True)
# sageresult = subprocess.check_output("ls -al")      
print sageresult
# print aa
# print bb
# bbb = np.mat(bb,dtype='float')
# aaa = np.mat(aa,dtype='float')
# print aaa

# a_abs = np.linalg.det(aaa)
# aok = int(round(a_abs))
# a_fy = np.linalg.inv(aaa)
# a_bansui = a_fy*a_abs

# print a_bansui,bbb
# print a_bansui[0]*bbb
# print round(np.array((a_bansui[0]*bbb)%m)[0][0])
# bok = int(round(np.array((a_bansui[0]*bbb)%m)[0][0]))
# print aok,bok
# ret =  ( gmpy2.invert(aok, m)* bok) %m
# 
# print ret

# ret = np.linalg.solve(np.array(aa), np.array(bb))
# print aaa[0]*bbb % m
io.sendline(sageresult)
print io.recv() 
# print io.recv() 
# print io.recv() 
# print io.recv() 
# print len(l)

