#include "fd_cache.h"
CFDCache *FDCacheNew() {
	CFDCache *r=calloc(1,sizeof(CFDCache));
	r->size=0;
	r->values=NULL;
	return r;
};
static size_t RoundUp(int fd) {
	return (fd&~127)+128*2;
}
void FDCacheSet(CFDCache *c,int fd,char *v) {
	if(fd<=0) return;
	char **new;
	if(fd>=c->size) {
		new=calloc(sizeof(char*),c->size=RoundUp(fd));
		if(c->values) memcpy(new,c->values,sizeof(char*)*c->size);
		free(c->values);
		c->values=new;
	}
	if(c->values[fd]) free(c->values[fd]);
	c->values[fd]=strdup(v);
}
void FDCacheRem(CFDCache *c,int fd) {
  if(fd<=0) return;
  if(fd<c->size) {
	  free(c->values[fd]);
	  c->values[fd]=NULL;
  }
};
void FDCacheDel(CFDCache *c) {
	long i=c->size;
	char *have;
	while(--i>=0) {
		if(have=c->values[i])
			free(have);
	}
	free(c->values);
	free(c);
}
	
char *FDCacheGet(CFDCache *c,int fd) {
	if(fd<=0) return NULL;
  if(fd<c->size) {
	  return c->values[fd];
  }
  return NULL;
}
