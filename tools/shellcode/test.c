#include <stdio.h>

// char shellcode[] = "\xeb\x19\x59";
// print "hello asm"
unsigned char shellcode[] = {
  0xeb, 0x19, 0x59, 0xb8, 0x04, 0x00, 0x00, 0x00, 0xbb, 0x01, 0x00, 0x00,
  0x00, 0xba, 0x0c, 0x00, 0x00, 0x00, 0xcd, 0x80, 0xb8, 0x01, 0x00, 0x00,
  0x00, 0xcd, 0x80, 0xe8, 0xe2, 0xff, 0xff, 0xff, 0x68, 0x65, 0x6c, 0x6c,
  0x6f, 0x20, 0x61, 0x73, 0x6d, 0x0a
};
unsigned int shellcode_bin_len = 42;

int main(){
  void (*fptr)() = shellcode;
  fptr();
}
