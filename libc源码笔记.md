[https://elixir.bootlin.com/glibc/](https://elixir.bootlin.com/glibc/)

prev_inuse: 检查**size**字段的最后一位, 如果是1则表明该块的前一块正在被使用.
```c
/* extract inuse bit of previous chunk */
#define prev_inuse(p)       ((p)->size & PREV_INUSE)
```


inuse: 检查当前块的**下一块的size**字段的最后一位, 如果是1则表明当前块正在被使用.
```c
/* extract p's inuse bit */
#define inuse(p)\
((((mchunkptr)(((char*)(p))+((p)->size & ~SIZE_BITS)))->size) & PREV_INUSE)
```

unlink: 
```c
/* Take a chunk off a bin list */
#define unlink(P, BK, FD) {                                            \
  FD = P->fd;                                                          \
  BK = P->bk;                                                          \
  if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                \
    malloc_printerr (check_action, "corrupted double-linked list", P); \
  else {                                                               \
    FD->bk = BK;                                                       \
    BK->fd = FD;                                                       \
    if (!in_smallbin_range (P->size)				       \
	&& __builtin_expect (P->fd_nextsize != NULL, 0)) {	       \
      assert (P->fd_nextsize->bk_nextsize == P);		       \
      assert (P->bk_nextsize->fd_nextsize == P);		       \
      if (FD->fd_nextsize == NULL) {				       \
	if (P->fd_nextsize == P)				       \
	  FD->fd_nextsize = FD->bk_nextsize = FD;		       \
	else {							       \
	  FD->fd_nextsize = P->fd_nextsize;			       \
	  FD->bk_nextsize = P->bk_nextsize;			       \
	  P->fd_nextsize->bk_nextsize = FD;			       \
	  P->bk_nextsize->fd_nextsize = FD;			       \
	}							       \
      }	else {							       \
	P->fd_nextsize->bk_nextsize = P->bk_nextsize;		       \
	P->bk_nextsize->fd_nextsize = P->fd_nextsize;		       \
      }								       \
    }								       \
  }                                                                    \
}
```

malloc_usable_size: 返回某个块中的可用字节数(`因为最小块大小和对齐的效果`, 这个大小可能比传给malloc的参数大). 常用于调试, 断言.
```c
p = malloc(n);
assert(malloc_usable_size(p) >= 256);
```

# arena
得到堆块所在堆的arena
```c
#define arena_for_chunk(ptr) \
  (chunk_non_main_arena (ptr) ? heap_for_ptr (ptr)->ar_ptr : &main_arena)
```

得到堆块所在堆的heap_info
```c
#define heap_for_ptr(ptr) \
  ((heap_info *) ((unsigned long) (ptr) & ~(HEAP_MAX_SIZE - 1)))
```

# 一些宏
## checked_request2size(req, sz)
检查传给malloc的参数sz的合法性, 若合法则将sz进行对齐

## bin_at(m, i)
m是malloc_state, i是大于0的整数. 取bins[(i-1) * 2], 再减去fd在chunk中的偏移(`说明bins数组中存的是malloc返回的地址.`). 返回的值为`malloc_chunk*`类型.

bins的每两个元素构成分别作为某条bins链的fd链和bk链, 所以这里返回的是`某条bins链的fd链`. 