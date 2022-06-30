#!/usr/bin/env python2
# I AM NOOB :)
import string
from hashlib import md5
from itertools import izip, cycle
import base64
import time
target='U1FEQEdeS1JDSEBEXlZDUEFYSG5ZQ29TVVBFRFlXRFxvUUJFTA=='

noobie = base64.decodestring(target).strip()
print noobie

def xor(data, key): 
    return bytearray(a^b for a, b in zip(*map(bytearray, [data, key]))) 

start=1589385600
scale = 16  
num_of_bits = 8 

for i in range(start, start+86400):
    key = md5(str(i)).hexdigest() 
    noobda = bin(int(key, scale))[2:].zfill(num_of_bits)
    #print noobda
    xorer = xor(noobie,noobda)
    if 'batpwn{' == xorer[0:7] and xorer[-1:] == '}' and '`' not in xorer and '^' not in xorer:
        print xorer
