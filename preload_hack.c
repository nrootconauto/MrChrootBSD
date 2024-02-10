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
