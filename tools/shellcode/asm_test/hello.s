section .text
global _start
_start:
    jmp msg
write:
    pop ecx
    mov eax,4
    mov ebx,1
    mov edx,12
    int 0x80

    mov eax,1
    int 0x80

msg:
    call write
    db 'hello asm',0xa
