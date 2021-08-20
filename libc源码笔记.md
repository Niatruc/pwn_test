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