#include <stdio.h>
#include <stdlib.h>

int main()
{
	char *buf[16];
	memset(buf, 0, sizeof(buf));
	read(0, buf, 32);
	printf("buf=%s\n", buf);
	exit(0);
}
