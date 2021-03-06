#include <stdio.h>
#include <stdlib.h>
#include <math.h>

int revert_word(char *w, char *end) {
    char *h = w, *t = end;
    
    if (*w == NULL) {
        return -1;
    }
    
    // while (*t != endc & *t != NULL) t++;
    // t--;

    while (h < t) {
        *t ^= *h;
        *h ^= *t;
        *t-- ^= *h++;
    }
    
    return 0;
}

int revert_sentence(char *s) {
    char *wh = s, *wt = s;
    if (*s == NULL) {
        return -1;
    }
    while (*wt != NULL) {
        while (*wt != ' ' && *wt != NULL) {
            wt++;
        }
        revert_word(wh, wt - 1);
        while (*wt == ' ') {
            wt++;
        }
        wh = wt;
    }
    revert_word(s, wt - 1);
    
    return 0;
}

int rotate_word(char *s, int cnt) {
    char *w1t = s + cnt - 1, *t;
    if (cnt <= 0) {
        return -1;
    }
    
    revert_word(s, w1t);
    t = w1t;
    while (*t != NULL) {
        t++;
    }
    revert_word(w1t + 1, t - 1);
    revert_word(s, t - 1);
    return 0;
}

typedef struct {
    char const *data;
    size_t next;
} node;

typedef struct
{
    node *head;
    node *tail;
    int len;
} double_linked_list;

double_linked_list *init_list() {
    double_linked_list *dl = (double_linked_list *) malloc(sizeof(double_linked_list));
    dl->head = NULL;
    dl->tail = NULL;
    dl->len = 0;
    return dl;
}

node *nodes[100] = {NULL};

int add_node(double_linked_list *dl, char const *data) {
    node *nd = (node *) malloc(sizeof(node));
    nd->data = data;
    nodes[dl->len] = nd;
    if (dl->len <= 0) {
        dl->head = nd;
        dl->tail = nd;
        nd->next = 0;
    } else {
        dl->tail->next ^= (size_t) nd;
        nd->next = (size_t) dl->tail;
        dl->tail = nd;
    }
    
    dl->len++;
    return 0;
}

int remove_node(double_linked_list *dl, int index) {
    node *last = NULL, *cur, *nd, *next;
    cur = dl->head;

    if (dl->len <= 0) {
        return -1;
    }

    for (int i = 0; i < index; i++) {
        if (cur == NULL) {
            return -1;
        }
        nd = cur;
        cur = (node *) ((size_t) last ^ (size_t) cur->next);
        last = nd;
    }
    if (cur != NULL) {
        next = (node *) ((size_t) cur->next ^ (size_t) last);
        
        if (last != NULL) {
            last->next ^= ((size_t) cur ^ (size_t) next);
        }
        if (next != NULL) {
            next->next ^= ((size_t) cur ^ (size_t) last);
        }
        if (cur == dl->head) {
            dl->head = next;
        }
        if (cur == dl->tail) {
            dl->tail = last;
        }
        
        dl->len--;
    } else {
        return -1;
    }
    

    return 0;
}

int iterate_list(double_linked_list *dl, bool from_head = true) {
    node *last = NULL, *cur, *nd;
    if (from_head) {
        cur = dl->head;
    } else {
        cur = dl->tail;
    }

    while (cur != NULL) {
        printf("%c", *(cur->data));
        fflush(stdout);
        nd = cur;
        cur = (node *) ((size_t) last ^ (size_t) cur->next);
        last = nd;
    }

    printf("\n");

    return 0;
}

int main(int argc, char const *argv[])
{
    /****************************************************/
    printf("?????????: ?????????????????????1?????????\n");

    int num = 0b1100101101,
        i = 0;
    while (num != 0) {
        num &= (num - 1);
        i ++;
    }

    printf("%d???1?????????: %d\n\n", num, i);

    /****************************************************/
    printf("?????????: 10?????????16??????\n");
    char elements[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int scale = sizeof(elements) - 1, l = 4;
    char c[l + 1] = {0};
    int test_cases[] = {1, 10, 20, 35, 36, 128};
    int quotient, remainder;
    for (int i = 0; i < sizeof(test_cases) / sizeof(int); i++)
    {
        int j = 1;
        quotient = test_cases[i];
        printf("%d: ", quotient);
        while (quotient != 0)
        {
            remainder = quotient % scale;
            quotient = quotient / scale;
            c[l - j++] = elements[remainder];
        }
        while (j <= l) {
            c[l - j++] = '0';
        }
        
        printf("%s", c);
        printf("\n");
    }
    printf("\n");
    
    /****************************************************/
    printf("?????????: ?????????????????????????????????\n");
    num = 1;
    char *p = (char *) &num;
    if (*p == 1) {
        printf("????????????\n");
    } else {
        printf("???????????????\n");
    }

    /****************************************************/
    printf("?????????: ????????????????????????\n");
    num = 0x12345678;
    unsigned int converted_num = 0;
    i = 0;
    while (num > 0) {
        converted_num = (converted_num << 8) + (char) num;
        num >>= 8;
    }
    printf("%x => %x\n", num, converted_num);
    printf("\n");
    
    /****************************************************/
    printf("?????????: ????????????\n");
    char test_str[] = "Hello world 123!";
    printf("??????: %s\n", test_str);
    revert_sentence(test_str);
    printf("?????????: %s\n", test_str);
    printf("\n");

    /****************************************************/
    printf("?????????: ???????????????\n");
    char test_str2[] = "Hello world 123!";
    rotate_word(test_str2, 3);
    printf("??????%d?????????: %s\n", 3, test_str2);
    printf("\n");
    
    /****************************************************/
    printf("?????????: ????????????????????????????????????????????????????????????\n");
    
    double_linked_list *dl = init_list();
    printf("?????????????????????:\n");
    add_node(dl, "H");
    iterate_list(dl);
    iterate_list(dl, false);

    add_node(dl, "e");
    iterate_list(dl);
    iterate_list(dl, false);

    add_node(dl, "l");
    add_node(dl, "l");
    add_node(dl, "o");
    iterate_list(dl);
    iterate_list(dl, false);

    printf("?????????????????????:\n");
    printf("???????????????2?????????:\n");
    remove_node(dl, 2);
    iterate_list(dl);
    iterate_list(dl, false);

    printf("???????????????0?????????:\n");
    remove_node(dl, 0);
    iterate_list(dl);
    iterate_list(dl, false);

    printf("???????????????2?????????:\n");
    remove_node(dl, 2);
    iterate_list(dl);
    iterate_list(dl, false);

    printf("???????????????2?????????:\n");
    remove_node(dl, 2);
    iterate_list(dl);
    iterate_list(dl, false);

    printf("???????????????0?????????:\n");
    remove_node(dl, 0);
    iterate_list(dl);
    iterate_list(dl, false);

    printf("???????????????0?????????:\n");
    remove_node(dl, 0);
    iterate_list(dl);
    iterate_list(dl, false);

    /****************************************************/
    return 0;
}
