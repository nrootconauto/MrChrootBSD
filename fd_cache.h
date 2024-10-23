#pragma once
#include <stdlib.h>
#define class(x)                                                               \
  typedef struct x x;                                                          \
  struct x
class (CFDCache) {
	size_t size;
	char **values;
};
void FDCacheDel(CFDCache *c);
CFDCache *FDCacheNew();
void FDCacheSet(CFDCache*,int,char*);
char *FDCacheGet(CFDCache*,int);
