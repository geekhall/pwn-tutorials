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

r=remote('95.216.233.106', 21833)

N=int(r.recvline()[2:-1])
print N
e=int(r.recvline()[2:-1])
print e
c=int(r.recvline()[3:-1])
print c

#N=p*q

#N=mpz(87924348264132406875276140514499937145050893665602592992418171647042491658461)
#e=65537
#N=mpz(322831561921859)
#e=23
#c=mpz(49412914049026066227292604633959399022586841904231599586841156187258952420473)
#c=int(open('flag.enc','rb').read().encode('hex'),16)

p, q = factordb(N)

#p = mpz()
#q = mpz()
#e = 17
#N = p*q 
phi = (p-1)*(q-1)
d = invert(e, phi)
print d
m = pow(c,d,N)
#c = powmod(m, e, N)
#d = invert(e, phi)
#m = pow(c,d,N)
#c = powmod(m, e, N)  

print "m :",m
print "n2s :",libnum.n2s(m)


