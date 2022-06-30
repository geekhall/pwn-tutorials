# coding:utf-8
#python solve.py -g --dumpkey --key jarvisoj/mediumRSA/pubkey.pem 
#python solve.py -g --enc2dec jarvisoj/mediumRSA/flag.enc 
#python solve.py -i jarvisoj/mediumRSA/exp.txt

from gmpy2 import *
import requests
import re
from Crypto.PublicKey import _slowmath
import subprocess
import libnum
import signal
import os
from pwn import *

'''
p: 8175470146086298061366233565739288351700428468784424598145069764792486185428094334670658445760852461083722164310285371936145832062226846731290359534874733
q: 11668468621154263716630907964301941086996525327353696106070673942340601642030964997422855167794564275235997723602774253960262581560156250254081789907962597
e: 65537
ct: 38908117778120052643124454088926711067266219503637571494666478774803119692090896696813126888886165834715484548250709031925645282412977280222974354474546168636222253158652673377542223912382491053272631956378103610906091746435706056668667178878468307568630017149760164288208831863890462765059804896043711892006

'''
def factordb(N):
    # if factordb returns some math to derive the prime, solve for p without using an eval
    def solveforp(equation):
        try:
            if '^' in equation:
                k, j = equation.split('^')
            if '-' in j:
                j, sub = j.split('-')
            eq = map(int, [k, j, sub])
            return pow(eq[0], eq[1]) - eq[2]
        except Exception as e:
            log.debug("FactorDB gave something we couldn't parse sorry (%s). Got error: %s" % (equation, e))
            raise FactorizationError()

    # Factors available online?
    try:
        url_1 = 'http://www.factordb.com/index.php?query=%i'
        url_2 = 'http://www.factordb.com/index.php?id=%s'
        s = requests.Session()
        r = s.get(url_1 % N)
        regex = re.compile("index\.php\?id\=([0-9]+)", re.IGNORECASE) 
        ids = regex.findall(r.text)
        p_id = ids[1]
        q_id = ids[2]
        regex = re.compile("value=\"([0-9\^\-]+)\"", re.IGNORECASE)
        r_1 = s.get(url_2 % p_id)
        r_2 = s.get(url_2 % q_id)
        key_p = regex.findall(r_1.text)[0]
        key_q = regex.findall(r_2.text)[0]
        p = int(key_p) if key_p.isdigit() else solveforp(key_p)
        q = int(key_q) if key_q.isdigit() else solveforp(key_q)
        if p == q == N:
            raise FactorizationError()
        return p, q
    except Exception:
        return

#普通算法，仅支持8位数
def factorDB(x): 
    for i in range(2, x-1):
        if ( x % i == 0 ):
            if is_prime(i):
                return i, x / i
    return 1, x
context(log_level='debug')

r=remote('95.216.233.106', 32259)
startFlag = False
nextFlag = False
n=0
phi=0
p=0
q=0
e=0
d=0
ct=0
pt=0
while True:
    head = r.recvuntil(']')
    #line = r.recvline()
    if head[:1] != '[':
        continue
    mode = head[1:2]
    if mode == '*':
        print 'in mode [*]'
        line = r.recvline()
        continue
    elif mode == 'c':
        print 'in mode [c]'
        startFlag = True
        n=0
        phi=0
        p=0
        q=0
        e=0
        d=0
        ct=0
        pt=0
        line = r.recvline()
        continue
    elif mode == '!':
        print 'in mode [!]'
        line = r.recvline()
        print line
        r.recvline()

        if 'Correct answer' in line:
            nextFlag = True
        continue
    elif mode == ':':
        print 'in mode [:]'
        line = r.recvline()
        #line = line[3:]
        pos = line.find(':')
        k = line[1:pos]
        print "kkk:" + k

        pos+=2
        if k == 'phi':
            phi = int(line[pos:])
            print 'phi:'+ str(phi)
        elif k == 'pt':
            pt = int(line[pos:])
            print 'pt:' + str(pt)
        elif k == 'p' :
            p = int(line[pos:])
            print 'p:'+ str(p)
        elif k == 'q':
            q = int(line[pos:])
            print 'q:'+ str(q)
        elif k == 'n':
            n = int(line[pos:])
            print 'n:'+ str(n)
        elif k == 'e':
            e = int(line[pos:])
            print 'e:' + str(e)
        elif k == 'd':
            d = int(line[pos:])
            print 'd:' + str(d)
        elif k == 'ct':
            ct = int(line[pos:])
            print 'ct:' + str(ct)
    elif mode == '?':
        print "in mode ?"
        #line = line[4:]
        line = r.recvuntil(': ')
        pos = line.find(':')
        print "ppppppos :" + str(pos)
        ques = line[1:pos]

        if p != 0 and q != 0:
            n = p*q
            phi = (p-1)*(q-1)
        
        if n != 0 and p != 0:
            q = n / p

        if n != 0 and q != 0:
            p = n / q 

        if phi != 0 and p != 0:
            q = phi / (p-1) + 1

        print '==========================================='
        print 'p  : ' + str(p)
        print 'q  : ' + str(q)
        print 'e  : ' + str(e)
        print 'n  : ' + str(n)
        print 'd  : ' + str(d)
        print 'phi: ' + str(phi)
        print 'pt : ' + str(pt)
        print 'ct : ' + str(ct)
        print 'ques :[' + str(ques) + ']'
        print '==========================================='
        if ques == 'phi':
            print 'in case ques=phi'
            phi = (p-1) * (q-1) 
            print 'phi:'+ str(phi)
            r.sendline(str(phi))
        elif ques == 'pt':
            print 'in case ques=pt'
            if p!=0 and phi != 0 and e!=0 and ct!=0:
                q = phi / (p-1) + 1
                n = p * q
                d = invert(e, phi)
                pt = pow(ct,d,n) 
                print 'pt:'+ str(pt)
                r.sendline(str(pt))
            else :
                print 'wow , not done'
        elif ques == 'p' :
            print 'in case ques=p'
            p = n / q 
            print 'p:'+ str(p)
            r.sendline(str(p))
        elif ques == 'q':
            print 'in case ques=q'
            q = n / p 
            print 'q:'+ str(q)
            r.sendline(str(q))
        elif ques == 'n':
            print 'in case ques=n'
            n = p*q
            print 'n:'+ str(n)
            r.sendline(str(n))
        elif ques == 'e':
            print 'in case ques=e'
            print 'e:' + str(e) 
            r.sendline(str(e))
        elif ques == 'd':
            print 'in case ques=d'
            if p != 0 and q!= 0 and e!=0:
                phi = (p-1) * (q-1) 
                d = invert(e, phi)
            print 'd:'+ str(d)
            r.sendline(str(d))
        elif ques == 'ct':
            print 'in case ques=ct'
            ct = powmod(pt, e, n)
            print 'ct:'+ str(ct)
            r.sendline(str(ct))
        else:
            print 'in case default'


#print "m :",m
#print "n2s :",libnum.n2s(m)


