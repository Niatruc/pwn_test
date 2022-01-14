#include <stdio.h>

typedef struct _node
{
    int data;
    struct _node *next;
} node, *pnode;

void init_node_list(node nds[], int cnt, int pt = -1) {
    for (size_t i = 0; i < cnt; i++) {
        nds[i].data = i;
        nds[i].next = &nds[i + 1];
    }
    nds[cnt - 1].data = cnt - 1;
    if (pt < 0) {
        nds[cnt - 1].next = NULL;
    } else {
        nds[cnt - 1].next = &nds[pt];
    }
}

int has_loop(node nds[]) {
    pnode n1 = nds, n2 = nds;
    while (n1 && n2) {
        n1 = n1->next;
        n2 = n2->next;
        if (n2) {
            n2 = n2->next;
        } else {
            return 0;
        }
        if (n1 == n2) {
            return 1;
        }
    }
    
    return 0;
}

pnode find_loop_entry(node nds[]) { // 找到被两个节点指向的那个节点
    pnode n1 = nds, n2;
    if (!nds || nds->next == nds) {
        return nds;
    }
    while (n1) {
        n1 = n1->next;
        n2 = nds;
        while (n2 != n1) {
            if (n1->next == n2) {
                return n2;
            }
            n2 = n2->next;
        }
    }
    
    return NULL;
}

// 寻找单向非循环链表倒数第m个节点
pnode find_countback_node(node nds[], int m) {
    pnode n1 = nds, n2 = nds;
    if (m < 0) return NULL;
    while (m && n1) {
        n1 = n1->next;
        m--;
    } 
    if (m > 0) return NULL;
    
    while (n1) {
        n1 = n1->next;
        n2 = n2->next;
    }

    return n2;
}

void print_list(node nds[], int cnt, int pt) {
    printf("列表: ");
    for (size_t i = 0; i < cnt; i++) {
        printf("%d -> ", nds[i].data);
    }
    if (pt < 0) {
        printf("NULL\n");
    } else {
        printf("%d\n", nds[pt].data);
    }
}

void test_loop_node_list(node nds[], int cnt, int pt) {
    int looped = 0;
    init_node_list(nds, cnt, pt);
    print_list(nds, cnt, pt);
    looped = has_loop(nds);
    if (looped) {
        printf("找到循环, ");
        pnode entry = find_loop_entry(nds);
        printf("入口: %d\n", entry->data);
    } else {
        printf("没有循环\n");
    }
}

void test_find_countback_node(node nds[], int cnt, int m) {
    init_node_list(nds, cnt, -1);
    print_list(nds, cnt, -1);
    pnode node_m = find_countback_node(nds, m);
    if (node_m) {
        printf("倒数第%d个节点为: %d\n", m, node_m->data);
    } else {
        printf("链表节点数小于%d\n", m);
    }
}

int main(int argc, char const *argv[])
{
    /* code */
    int cnt = 5;
    int looped = 0;
    node nds[5] = {0};
    test_loop_node_list(nds, 5, -1); // 非循环链表
    test_loop_node_list(nds, 5, 0);
    test_loop_node_list(nds, 5, 2);

    node nds2[1] = {0};
    test_loop_node_list(nds2, 1, -1); // 非循环链表
    test_loop_node_list(nds2, 1, 0);

    printf("\n");

    node nds3[6] = {0};
    test_find_countback_node(nds3, 6, 0);
    test_find_countback_node(nds3, 6, 1);
    test_find_countback_node(nds3, 6, 6);
    test_find_countback_node(nds3, 6, 7);
    
    return 0;
}
