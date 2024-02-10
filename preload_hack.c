#include "nrchroot.h";
#include <sys/auxv.h>
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
//Dont let the linker leak information about the parent enviorment
int elf_aux_info(int which,void *buf,int bs) {
	int(*elf_poop_pt2)(int which,void *buf,int bs)=(void*)dlsym(RTLD_NEXT,"elf_aux_info");
	if(which==AT_EXECPATH) {
		errno=ENOENT;
		return -1;
	}
	return (*elf_poop_pt2)(which,buf,bs);
}
static char *SkipWhitespace(char *p) {
	while(*p&&isblank(*p))
	  p++;
	return p;
}
int execve(const char *path, char *const argv[], char *const envp[]) {
	int(*moonwalking)(char*,char**,char**)=(void*)dlsym(RTLD_NEXT,"execve");
	char buf[1024],*ptr;
	int64_t r,s,e,a,tmp;
	if(access(path,F_OK))
	  return 1;
	FILE *f=fopen(path,"rb");
	r=fread(buf,1,1023,f);
	buf[r]=0;
	if(buf[0]=='#'&&buf[1]=='!') {
		if(strchr(buf,'\n')) {
			*strchr(buf,'\n')=0;
			r=strlen(buf);
			for(s=2;s!=r;s++) {
				if(!isblank(buf[s]))
				break;
			}
			for(e=s;e!=r;e++) {
				if(isblank(buf[e])) {
					buf[e]=0;
					break;
				}
			}
			fclose(f);
			char *buf2[256];
			a=0;
			buf2[a++]=&buf[s]; // /bin/sh
			//Handle args... #! /bin/sh [args]
			if(e!=r) {
			  ptr=&buf[e+1];
			  while(ptr-(char*)buf<r) {
				  ptr=SkipWhitespace(ptr);
				  buf2[a++]=ptr;
				  while(*ptr&&!isblank(*ptr))
					ptr++;
				  *ptr++=0;
 			  }
			}
			buf2[a++]=path; //  /bin/man
			tmp=a;
			if(argv[0]) //argv[0] is path name so ignore
				while(argv[a-tmp+1]) {
					buf2[a]=argv[a-tmp+1];
					a++;
				}
			buf2[a++]=NULL;
			execve(&buf[s],buf2,envp);
		}
	}
	fclose(f);
	return (*moonwalking)(path,argv,envp);
}
