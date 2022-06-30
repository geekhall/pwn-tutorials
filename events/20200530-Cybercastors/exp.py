from pwn import *
context(log_level="debug")
p = remote('chals20.cybercastors.com', 14429)
ops=['multiplied-by','divided-by','minus','plus','+','-','*','/','//']

nums={'one' : '1',
      'two' : '2',
      'three' : '3',
      'four' : '4',
      'five' : '5',
      'six' : '6',
      'seven' : '7',
      'eight' : '8',
      'nine' : '9',
      'ten' : '10',
      'divided-by' : '/',
      'minus' : '-',
      'plus' : '+',
      'multiplied-by' : '*'
      }

def conv(num):
    for key in nums.keys():
        num = num.replace(key, nums[key])
    return num

def calc(strs):
    for op in ops:
        if op in strs:
            print(op)
            pos = strs.find(op)
            print(pos)
            print(strs)
            a = int(strs[0: pos])
            b = int(strs[pos + 2:])
            if op == '+': 
                c = a + b
            elif op == '-': 
                c = a - b
            elif op == '*': 
                c = a * b
            elif op == '//':
                c = a // b
            elif op == '/': 
                c = a / b
            return c




p.recvuntil('Hit <enter> when ready.\n')
p.sendline('\n')

while True:
    recvstr=p.recvuntil('?')
    pos = recvstr.find('is')
    pos = pos + 2
    expr=recvstr[pos:-1]
    expr = conv(expr)
    ans=calc(expr)
    p.sendline(str(ans))
    #res = p.recvline()
    #print res
    #p.recvline()

p.interactive()

