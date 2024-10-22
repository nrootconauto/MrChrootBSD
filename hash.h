#pragma once
#include <unistd.h>
#define class(x)                                                               \
  typedef struct x x;                                                          \
  struct x
class(CHashEntry) {
	uint32_t perms;
	uid_t uid;
	gid_t gid;
};
void HashTableSet(const char *fn,uid_t u,gid_t g,uint32_t perms);
CHashEntry *HashTableGet(CHashEntry *e,const char *fn);
void HashTableRemove(const char *fn);
void HashTableInit(const char *fn);
void HashTableDone() ;
