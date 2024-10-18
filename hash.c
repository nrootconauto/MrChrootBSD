#include "hash.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <db.h>
#include <fcntl.h>
#include <limits.h>
#define DB_MAGIC "#CSV-like file,has format uid\tgid\tname\n" \
	"# Dont edit by hand\n"

static uint32_t HashStr(const void *f,size_t sz) {
//djb2
    uint8_t *ff=(uint8_t*)f;
	uint32_t r=5831;
	while((long)(--sz)>=0) {
		r*=31;
		r+=*(ff++);
	}
	return r;
}
static 	DB *perms_db=NULL;
void HashTableInit(const char *name) {
	HASHINFO hi;
	hi.bsize=4096;
	hi.ffactor=8;
	hi.nelem=1;
	hi.cachesize=1024;
	hi.hash=&HashStr;
	hi.lorder=0;
	perms_db=dbopen(name,O_RDWR|O_CREAT,0644,DB_HASH,&hi);	
}
//Returns static entry on e==NULL
CHashEntry *HashTableGet(CHashEntry *e,const char *fn) {
	CHashEntry dummy;
	DBT key={fn,strlen(fn)},res={&dummy,sizeof(CHashEntry)};
	static CHashEntry st;
	if(!e) e=&st;
	if(!perms_db->get(perms_db,&key,&res,0)) {
		if(e&&res.size==sizeof(CHashEntry)) {
			memcpy(e,res.data,sizeof(CHashEntry));
			return e;
		}
	}
	return NULL;
}
void HashTableSet(const char *fn,uid_t u,gid_t g,uint32_t perms) {
	CHashEntry ent={perms,u,g};
	DBT key={fn,strlen(fn)},data={&ent,sizeof(ent)};
	perms_db->put(perms_db,&key,&data,0);
}
void HashTableRemove(const char *fn) {
	DBT key={fn,strlen(fn)};
	perms_db->del(perms_db,&key,0);
}
void HashTableDone() {
	perms_db->close(perms_db);
}
