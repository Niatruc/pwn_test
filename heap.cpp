// https://www.xuenixiang.com/thread-57-1-1.html

/* 
gcc heap.c -m64 -z execstack -fno-stack-protector -no-pie -o heap_libc_2_23 
    -Wl,--rpath=/home/bohan/res/ubuntu_share/tools/glibc-all-in-one/libs/2.23-0ubuntu3_amd64 
    -Wl,--dynamic-linker=/home/bohan/res/ubuntu_share/tools/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/ld-linux-x86-64.so.2
*/

// #include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void sh(char *id)
{
	system(id);
}

int PtrLen = sizeof(size_t);

int main(int argc, char const *argv[])
{
	int chunkNum = 10;
	if (argc > 1)
	{
		chunkNum = atoi(argv[1]);
	}

#define chunkMData(mem, i) ((size_t)mem[(i - 2) * PtrLen])

#define putsChunk()                                                                         \
	{                                                                                       \
		idx %= chunkNum;                                                                    \
		printf("chunk_addr: %p (%p)\n", segsPtrs[idx] - sizeof(size_t) * 2, segsPtrs[idx]); \
		printf("prev_size: %p\t", chunkMData(segsPtrs[idx], 0));                            \
		printf("size: %p\n", chunkMData(segsPtrs[idx], 1));                                 \
		printf("fd: %p\t", chunkMData(segsPtrs[idx], 2));                                   \
		printf("bk: %p\t", chunkMData(segsPtrs[idx], 3));                                   \
		printf("fd_nextsize: %p\t", chunkMData(segsPtrs[idx], 4));                          \
		printf("bk_nextsize: %p\n", chunkMData(segsPtrs[idx], 5));                          \
		printf("内容: ");                                                                   \
		puts(segsPtrs[idx]);                                                                \
		printf("\n");                                                                       \
	}

	printf("pid: %d\n", getpid());
	char **segsPtrs = new char *[chunkNum];

	setvbuf(stdout, 0, _IONBF, 0);
	void *p;
	char c = 'c';
	int bufSize = 0x100;
	size_t buf[bufSize];
	int cmd, idx, total = 0, sz, chunkSz, n;
	// char *ptr[10];
	// memset(ptr, 0, sizeof(ptr));
	puts("1.malloc+gets\n2.malloc+gets\n4.puts\n5.modify\n6.delete\n7.list\n8.detailed list\n");
	while (1)
	{
		printf("> ");
		// setbuf(stdin, NULL);
		stdin->_IO_read_ptr = stdin->_IO_read_end;
		scanf("%d", &cmd);
		if (cmd == 1) // malloc
		{
			puts("输入区域大小(字节)及内容: ");
			scanf("%d%*c", &sz);
			segsPtrs[total] = (char *)malloc(sz);
			fgets(segsPtrs[total], sz + 1, stdin); // 这里fgets只最多读取sz个字符, 如果还没够数量而遇到换行符, 就会把换行符存起来
			total++;
		}
		else if (cmd == 2) // calloc
		{
			puts("输入元素个数, 元素大小(字节)及内容: ");
			scanf("%d%d%*c", &n, &sz);
			segsPtrs[total] = (char *)calloc(n, sz);
			fgets(segsPtrs[total], sz, stdin);
			total++;
		}
		else if (cmd == 4) // puts
		{
			if (total > 0)
			{
				puts("输入要打印的区域的id: ");
				scanf("%d", &idx);
				putsChunk();
			}
		}
		else if (cmd == 5) // modify
		{
			puts("输入要编辑的区域的id, 并输入内容: ");
			scanf("%d%*c", &idx);
			// sz = (size_t)segsPtrs[idx][-1 * PtrLen] & ~0x7 - PtrLen * 2;
			scanf("%s", segsPtrs[idx]);
			// fgets(segsPtrs[idx], ~0, stdin);
		}
		else if (cmd == 6) // delete
		{
			puts("输入要删除的区域的id: ");
			scanf("%d", &idx);
			free(segsPtrs[idx]);
		}
		else if (cmd == 7) // list
		{
			for (idx = 0; idx < total; idx++)
			{
				printf("%d: %s", idx, segsPtrs[idx]);
			}
		}
		else if (cmd == 8) // detailed list
		{
			for (idx = 0; idx < total; idx++)
			{
				printf("%d\n", idx);
				putsChunk();
			}
		}
		else if (cmd == 9) // 打印某地址的内存值
		{
			scanf("%p", &p);
			memcpy(buf, p, bufSize);
			for (int i = 0, j = 1; i < bufSize; i++, j %= 2)
			{
				printf("0x%llx ", buf[i]);
				if (j++ == 0)
				{
					printf("\n");
				}
				
			}
		}
		else
		{
			// printf("0x%llx ", c);
			exit(0);
		}
	}
	return 0;
}