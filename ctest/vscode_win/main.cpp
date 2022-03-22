#include <stdio.h>
#include <string.h>
int main(int argc, char const *argv[])
{
    char s[] = "abcd";
    strcpy(s, "eeeeffff\x0c\x0c\x0c\x0c");
    return 0;
}
