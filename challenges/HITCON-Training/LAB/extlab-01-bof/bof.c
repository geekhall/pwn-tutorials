#include <stdio.h>
#include <stdlib.h>

void l33t(){
  puts("Congrat !!");
  system("/bin/sh");
}

int main(){
  char buf[20];
  puts("Buffer overflow is easy");
  printf("Read your input :");
  fflush(stdout);
  read(0, buf, 100);
  return 0;
}
