#include <dlfcn.h>
#include <errno.h>
#include <sys/auxv.h>

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
