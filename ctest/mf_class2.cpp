#include <stdio.h>

char *strstr(char *str, char *subStr) {
    char *s1 = str, *s2 = subStr, *cur;
    int i = 0;
    while (s1 != NULL) {
        cur = s1;
        s2 = subStr;
        while (s1 && s2 && *s1 == *s2) {
            s1++;
            s2++;
        }
        if (*s2 == NULL) {
            return cur;
        }
        if (*s1 == NULL) {
            return NULL;
        }
        i++;
        s1 = str + i;
    }
    
    
    return 0;
}

int main(int argc, char const *argv[])
{
    char *testStrs[] = {
        "hello world",
        "123",
    };
    char *res, *subStr;

    subStr = "ldh\0";
    res = strstr(testStrs[0], subStr);
    printf("\"%s\"和\"%s\" -> %d\n", testStrs[0], subStr, res);
    
    subStr = "hel\0";    
    res = strstr(testStrs[0], subStr);
    printf("\"%s\"和\"%s\" -> %s\n", testStrs[0], subStr, res);

    subStr = "orl\0";
    res = strstr(testStrs[0], subStr);
    printf("\"%s\"和\"%s\" -> %s\n", testStrs[0], subStr, res);

    return 0;
}
