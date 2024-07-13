#include "mrchroot.h"
#include <dlfcn.h>
#include <errno.h>
#include <sys/auxv.h>
#include	<sys/syscall.h>
#include	<unistd.h>
#include <stdio.h>
#include <stdlib.h>
// Dont let the linker leak information about the parent enviorment
__attribute__((visibility("default")))
int elf_aux_info(int which, void *buf, int bs) {
  typeof(elf_aux_info) *sym = dlsym(RTLD_NEXT, "elf_aux_info");
  if (which == AT_EXECPATH) {
    errno = ENOENT;
    return -1;
  }
  return sym(which, buf, bs);
}
static char chroot_address[4048];
__attribute__((constructor)) static void LoadHacks() {
    static char data_zone[0x10000];
	static CMrChrootHackPtrs hacks={
		data_zone,
		NULL //todo
	};
	//This uses a indeirect syscall
	__syscall(MR_CHROOT_NOSYS,&hacks,chroot_address);
}
