#pragma once
#include <stdlib.h>
#define class(x)                                                               \
  typedef struct x x;                                                          \
  struct x
class (CFDCache) {
	size_t size;
	char **values;
};
extern char *fd_cache_none;
#define FD_CACHE_NOT_FILE fd_cache_none //Perhaps a network socket or pipe
void FDCacheDel(CFDCache *c);
CFDCache *FDCacheNew();
void FDCacheSet(CFDCache*,int,char*);
char *FDCacheGet(CFDCache*,int);
