// https://www.xuenixiang.com/thread-57-1-1.html

/* 
gcc heap.c -m64 -z execstack -fno-stack-protector -no-pie -o heap_libc_2_23 
    -Wl,--rpath=/home/bohan/res/ubuntu_share/tools/glibc-all-in-one/libs/2.23-0ubuntu3_amd64 
    -Wl,--dynamic-linker=/home/bohan/res/ubuntu_share/tools/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/ld-linux-x86-64.so.2
*/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>

void sh(char *id)
{
        system(id);        
}

int main()
{
        setvbuf(stdout,0,_IONBF,0);
        int cmd,idx,sz;
        char *ptr[10];
        memset(ptr,0,sizeof(ptr));
        puts("1.malloc+gets\n2.free\n3.puts\n4.modify\n");
        while(1)
        {
                printf("> ");
                scanf("%d %d",&cmd,&idx); //这里cmd是选择功能，idx是为了区分申请的第几个chunk
                idx %= 10;
                if(cmd==1)
                {
                        scanf("%d%*c",&sz);
                        ptr[idx] = malloc(sz);
                        gets(ptr[idx]);
                }
                else if(cmd==2)
                {
                        free(ptr[idx]);
                }
                else if(cmd==3)
                {
                        puts(ptr[idx]);
                }
                else if(cmd==4)
                {
                        gets(ptr[idx]);
                }
                else
                {
                        exit(0);
                }
        }
        return 0;
}