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

int execve(const char *path, char *const argv[], char *const envp[]) {
	int(*moonwalking)(char*,char**,char**)=(void*)dlsym(RTLD_NEXT,"execve");
	char buf[1024];
	int64_t r,s,e,a;
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
			//TODO account for #! /bin/sh -args
			buf2[a++]=&buf[s]; // /bin/sn
			buf2[a++]=path; //  /bin/man
			while(argv[a-2]) {
				buf2[a]=argv[a-2];
				a++;
			}
			buf2[a++]=NULL;
			execve(&buf[s],buf2,envp);
		}
	}
	fclose(f);
	return (*moonwalking)(path,argv,envp);
}
