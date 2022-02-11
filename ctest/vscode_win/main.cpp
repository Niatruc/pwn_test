#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct _node {
    char data;
    _node *next;
} node, *pnode;

pnode build_link_list(char *data) {
    int linkListLen = strlen(data);
    if (linkListLen <= 0) return NULL;
    pnode headNd = (pnode) malloc(sizeof(node));
    headNd->data = data[0];
    pnode nextNd = headNd;
    for (size_t i = 1; i < linkListLen; i++) {
        pnode nd = (pnode) malloc(sizeof(node));
        nd->data = data[i];
        nextNd->next = nd;
        nextNd = nd;
    }
    nextNd->next = NULL;
    return headNd;
}

void print_link_list(pnode linkList) {
    pnode p = linkList;
    printf("打印链表: ");
    while (p) {
        printf("%c ", p->data);
        p = p->next;
    }
    printf("\n");
}

pnode reverse_link_list(pnode linkList) {
    pnode p1 = NULL, p2 = linkList, p, tailNode = linkList;

    while (p2) {
        p = p2->next;
        if (!p) tailNode = p2;
        p2->next = p1;
        p1 = p2;
        p2 = p;
    }
    return tailNode;
}

pnode insert_sort_link_list(pnode linkList) {
    pnode p = NULL, q, r, insertedNd = NULL, sortedList = linkList;
    if (sortedList) {
        p = sortedList->next;
        sortedList->next = NULL;
    } 
    while (p) {
        insertedNd = p;
        p = p->next;
        insertedNd->next = NULL; // 将待插入节点从原链表中取出
        q = sortedList;
        r = NULL;
        while (q) { // q在已排序链表中移动; 将insertedNd插入到已排序链表中
            if (insertedNd->data < q->data) {
                if (r) {
                    r->next = insertedNd;
                }
                insertedNd->next = q;
                break;
            } else {
                r = q;
                q = q->next;
            } 
        }
        if (!r) sortedList = insertedNd; // 表明插在了队头

        // 若q到了已排序链表队尾, 则在队尾插入insertedNd
        if (!q) r->next = insertedNd;
    }
    return sortedList;
}

// 递归法, 将当前节点连到右边的已逆置链表的末尾
pnode reverse_link_list_recur(pnode linkList, pnode &origTail) {
    if (linkList) {
        if (linkList->next == NULL) origTail = linkList; // 找到尾部节点, 记录下来

        pnode subRevLinkListTail = reverse_link_list_recur(linkList->next, origTail); // 返回逆置后的链表的尾部节点
        linkList->next = NULL;
        if (subRevLinkListTail) {
            subRevLinkListTail->next = linkList;
        }
    }
    return linkList;
}

int del_node_from_link_list(pnode linkList, pnode delNd) {
    if (!linkList || !delNd) return -1;

    pnode nextNd = delNd->next;
    if (nextNd) {
        delNd->data = nextNd->data;
        delNd->next = nextNd->next;
    } else {
        pnode p = linkList;
        while (p && p->next != delNd) {
            p = p->next;
        }
        if (p && p->next == delNd) {
            p->next = delNd->next;
        }
    }
    return 0;
}

void test_reverse_link_list(char *data) {
    pnode linkList;
    linkList = build_link_list(data);

    print_link_list(linkList);

    pnode tailNd = NULL;
    printf("递归法逆置链表...\n");
    reverse_link_list_recur(linkList, tailNd);
    print_link_list(tailNd);

    linkList = build_link_list("helloworld!");
    printf("非递归法逆置链表...\n");
    tailNd = reverse_link_list(linkList);
    print_link_list(tailNd);

    printf("\n");
}

void test_sort_link_list(char *data) {
    pnode linkList;
    linkList = build_link_list(data);

    print_link_list(linkList);

    printf("插入法链表排序...\n");
    pnode sortedLinkList = insert_sort_link_list(linkList);
    print_link_list(sortedLinkList);

    printf("\n");
}

void test_del_nd_from_link_list(char *data) {
    pnode linkList;
    linkList = build_link_list(data);

    print_link_list(linkList);

    printf("删除最后一个节点: \n");
    pnode p = linkList;
    while (p && p->next) {
        p = p->next;
    }
    del_node_from_link_list(linkList, p);
    print_link_list(linkList);
    
    printf("删除第二个节点: \n");
    p = linkList->next;
    del_node_from_link_list(linkList, p);
    print_link_list(linkList);

    printf("\n");
}

int main(int argc, char const *argv[])
{
    test_reverse_link_list("helloworld!");
    test_reverse_link_list("");
    test_reverse_link_list("h");
    printf("\n");
    test_sort_link_list("helloworld!");
    test_sort_link_list("");
    test_sort_link_list("h");
    printf("\n");

    test_del_nd_from_link_list("helloworld!");
    return 0;
}
