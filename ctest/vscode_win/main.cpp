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
    printf("��ӡ����: ");
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
        insertedNd->next = NULL; // ��������ڵ��ԭ������ȡ��
        q = sortedList;
        r = NULL;
        while (q) { // q���������������ƶ�; ��insertedNd���뵽������������
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
        if (!r) sortedList = insertedNd; // ���������˶�ͷ

        // ��q���������������β, ���ڶ�β����insertedNd
        if (!q) r->next = insertedNd;
    }
    return sortedList;
}

// �ݹ鷨, ����ǰ�ڵ������ұߵ������������ĩβ
pnode reverse_link_list_recur(pnode linkList, pnode &origTail) {
    if (linkList) {
        if (linkList->next == NULL) origTail = linkList; // �ҵ�β���ڵ�, ��¼����

        pnode subRevLinkListTail = reverse_link_list_recur(linkList->next, origTail); // �������ú�������β���ڵ�
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
    printf("�ݹ鷨��������...\n");
    reverse_link_list_recur(linkList, tailNd);
    print_link_list(tailNd);

    linkList = build_link_list("helloworld!");
    printf("�ǵݹ鷨��������...\n");
    tailNd = reverse_link_list(linkList);
    print_link_list(tailNd);

    printf("\n");
}

void test_sort_link_list(char *data) {
    pnode linkList;
    linkList = build_link_list(data);

    print_link_list(linkList);

    printf("���뷨��������...\n");
    pnode sortedLinkList = insert_sort_link_list(linkList);
    print_link_list(sortedLinkList);

    printf("\n");
}

void test_del_nd_from_link_list(char *data) {
    pnode linkList;
    linkList = build_link_list(data);

    print_link_list(linkList);

    printf("ɾ�����һ���ڵ�: \n");
    pnode p = linkList;
    while (p && p->next) {
        p = p->next;
    }
    del_node_from_link_list(linkList, p);
    print_link_list(linkList);
    
    printf("ɾ���ڶ����ڵ�: \n");
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
