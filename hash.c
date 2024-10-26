#include "hash.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <db.h>
#include <fcntl.h>
#include <limits.h>
#include "mrchroot.h"
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
	hi.bsize=2048*2;
	hi.ffactor=8;
	hi.nelem=1;
	hi.cachesize=1024;
	hi.hash=&HashStr;
	hi.lorder=0;
	perms_db=dbopen(name,O_RDWR|O_CREAT,0644,DB_HASH,&hi);	
	atexit(&HashTableDone);
}
static void HashSync() {
	static int64_t cnt=0;
	while((cnt++&255)==0)
	  perms_db->sync(perms_db,0);
}
//Returns static entry on e==NULL
CHashEntry *HashTableGet(CHashEntry *e,const char *fn_) {
	char dummyfn[1024];
	char *fn=DatabasePathForFile(dummyfn,fn_);
	if(!fn) return NULL;
	
	CHashEntry dummy;
	DBT key={fn,strlen(fn)},res={&dummy,sizeof(CHashEntry)};
	static CHashEntry st;
	if(!e) e=&st;
	if(!strcmp(fn,"/")) {
		e->uid=0;
		e->gid=0;
		e->perms=755;
		return e;
	}
	if(!perms_db->get(perms_db,&key,&res,0)) {
		if(e&&res.size==sizeof(CHashEntry)) {
			memcpy(e,res.data,sizeof(CHashEntry));
			return e;
		}
	}
	return NULL;
}
void HashTableSet(const char *fn_,uid_t u,gid_t g,uint32_t perms) {
	char dummyfn[1024];
	char *fn=DatabasePathForFile(dummyfn,fn_);
	if(!fn) return;
	if(!strcmp(fn,"/")) return ; //No way
	CHashEntry ent={perms,u,g};
	DBT key={fn,strlen(fn)},data={&ent,sizeof(ent)};
	perms_db->put(perms_db,&key,&data,0);
	HashSync();	
}
void HashTableRemove(const char *fn_) {
	char dummyfn[1024];
	char *fn=DatabasePathForFile(dummyfn,fn_);
	if(!fn) return;
	if(!strcmp(fn,"/")) return ; //No way
	DBT key={fn,strlen(fn)};
	perms_db->del(perms_db,&key,0);
	HashSync();	
}
void HashTableDone() {
	if(!perms_db) return;
	perms_db->close(perms_db);
	perms_db=NULL;
}
	
