#include <stdio.h>

void del_char(char *str, char del) {
    int delLen = 0;
    char *p1, *p2;
    p1 = p2 = str;
    while (*p1 && *p1 != del) {
        p1++;
    }
    while (*p1) {
        while (*p1 == del) {
            delLen++;
            p1++;
        }
        p2 = p1;
        while (delLen > 0 && *p2 && *p2 != del) {
            *(p2 - delLen) = *(p2++);
        }
        p1 = p2;

        // ÉèÖÃ½áÎ²µÄNULL
        if (*p1 == NULL) {
            *(p1 - delLen) = NULL;
        }
    }
}

void test_del_char(char *str, char del) {
    printf("Ô­×Ö·û´®: %s\n", str);
    del_char(str, del);
    printf("É¾³ý×Ö·û'%c'ºó: %s\n\n", del, str);
}

void del_chars(char *str, char del[], size_t n) {
    bool del_h[256] = {false};
    for (size_t i = 0; i < n; i++) {
        del_h[(int) del[i]] = true;
    }
    
    int delLen = 0;
    char *p1, *p2;
    p1 = p2 = str;
    while (*p1 && !del_h[(int) *p1]) {
        p1++;
    }
    while (*p1) {
        while (del_h[(int) *p1]) {
            delLen++;
            p1++;
        }
        p2 = p1;
        while (delLen > 0 && *p2 && !del_h[(int) *p2]) {
            *(p2 - delLen) = *(p2++);
        }
        p1 = p2;

        // ÉèÖÃ½áÎ²µÄNULL
        if (*p1 == NULL) {
            *(p1 - delLen) = NULL;
        }
    }
}

void test_del_chars(char *str, char del[], size_t n) {
    printf("Ô­×Ö·û´®: %s\n", str);
    del_chars(str, del, n);
    printf("É¾³ý×Ö·û'%s'ºó: %s\n\n", del, str);
}

int main(int argc, char const *argv[])
{
    char str1[] = "hello world!";
    char str2[] = "h";
    char str3[] = "";

    test_del_char(str1, 'l');
    test_del_char(str1, 'h');
    test_del_char(str1, '!');
    test_del_char(str1, 0);

    test_del_char(str2, 'h');

    test_del_char(str3, 'l');

    char str4[] = "hello world!";
    char str5[] = "h";
    char str6[] = "";

    test_del_chars(str4, "l", 1);
    test_del_chars(str4, "ho", 2);
    test_del_chars(str4, "!", 1);
    test_del_chars(str4, "\0", 1);

    test_del_chars(str5, "h", 1);

    test_del_chars(str6, "l", 1);

    return 0;
}
