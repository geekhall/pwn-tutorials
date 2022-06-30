# -*- coding:utf-8 -*-

from pwn import *
import math
context(log_level='debug')

def hcf(x, y):
    """该函数返回两个数的最大公约数"""

    # 获取最小值
    if x > y:
        smaller = y
    else:
        smaller = x

    for i in range(1, smaller + 1):
        if ((x % i == 0) and (y % i == 0)):
            hcf = i

    return hcf

p = remote('chall.csivit.com', 30827)

while True: 
    line = p.recvline()
    if line == 'Hey, you got me!\n':
        break
    line = line.replace('\n', '')
    a, b = line.split(' ')
    a = int(a)
    b = int(b)
    c = hcf(a,b)
    d = math.factorial(c + 3)
    p.sendline(str(d))

p.recvline()
p.recvline()
p.interactive()


