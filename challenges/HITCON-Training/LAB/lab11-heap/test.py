from pwn import *

print "aaaa".ljust(8,'\x00')

str = fit({ 32: 0xdeadbeef, 'iaaa': [1, 2, 'Hello', 3] }, length=128)
print str
