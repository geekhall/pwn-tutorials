## compile

```bash
nasm -felf32 hello.s -o hello.o
```

## link

```bash
ld hello.o -melf_i386 -o hello
```

## copy shellcode

```bash
objcopy -O binary hello shellcode.bin
```

## show shellcode

```bash
xxd shellcode.bin
```

显示：

```
00000000: eb19 59b8 0400 0000 bb01 0000 00ba 0c00  ..Y.............
00000010: 0000 cd80 b801 0000 00cd 80e8 e2ff ffff  ................
00000020: 6865 6c6c 6f20 6173 6d0a                 hello asm.
```

或者使用`xxd -i shellcode.bin`，得到：

```c
unsigned char shellcode_bin[] = {
  0xeb, 0x19, 0x59, 0xb8, 0x04, 0x00, 0x00, 0x00, 0xbb, 0x01, 0x00, 0x00,
  0x00, 0xba, 0x0c, 0x00, 0x00, 0x00, 0xcd, 0x80, 0xb8, 0x01, 0x00, 0x00,
  0x00, 0xcd, 0x80, 0xe8, 0xe2, 0xff, 0xff, 0xff, 0x68, 0x65, 0x6c, 0x6c,
  0x6f, 0x20, 0x61, 0x73, 0x6d, 0x0a
};
unsigned int shellcode_bin_len = 42;
```