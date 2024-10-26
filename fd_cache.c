#include "fd_cache.h"
CFDCache *FDCacheNew() {
	CFDCache *r=calloc(1,sizeof(CFDCache));
	r->size=0;
	r->values=NULL;
	return r;
};
char *fd_cache_none="";
static size_t RoundUp(int fd) {
	return (fd&~127)+128*2;

}
void FDCacheSet(CFDCache *c,int fd,char *v) {
	if(fd<=0) return;
        if(fd>=1024) return;
	char **new;
	if(fd>=c->size) {
		new=calloc(1,sizeof(char*)*RoundUp(fd));
		if(c->values) memcpy(new,c->values,sizeof(char*)*c->size);
		c->size=RoundUp(fd);
		free(c->values);
		c->values=new;
	}
	if(FD_CACHE_NOT_FILE!=c->values[fd]) free(c->values[fd]);
	if(v==FD_CACHE_NOT_FILE) c->values[fd]=FD_CACHE_NOT_FILE;
	else c->values[fd]=strdup(v);
}
void FDCacheRem(CFDCache *c,int fd) {
  if(fd<=0) return;
  char *have;
  if(fd<c->size) {
	  have=c->values[fd];
	  if(have!=FD_CACHE_NOT_FILE&&have)
		free(have);
	  c->values[fd]=NULL;
  }
};
void FDCacheDel(CFDCache *c) {
	long i=c->size;
	char *have;
	while(--i>=0) {
		if(have=c->values[i])
		    if(have!=FD_CACHE_NOT_FILE)
				free(have);
	}
	free(c->values);
	free(c);
}
	
char *FDCacheGet(CFDCache *c,int fd) {
	if(fd<=0) return NULL;
	if(fd>=1024) return NULL;
  if(fd<c->size) {
	  return c->values[fd];
  }
  return NULL;
}
