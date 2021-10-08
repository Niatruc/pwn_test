#include <stdio.h>

// gcc ret2stack.c -fno-stack-protector -Wl,-z,relro,-z,now,-z,noexecstack -static -o ret2stack
int main()
{
  char buf[64];

  gets(buf);
  printf("%s", buf);
  return 0;
}