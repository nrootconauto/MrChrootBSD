#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/types.h>

#include "ptrace.h"

static size_t ptracerw(int op, pid_t pid, void *buf, void *addr, size_t len) {
  struct ptrace_io_desc iod = {
    .piod_op = op,
    .piod_offs = addr,
    .piod_addr = buf,
    .piod_len = len,
  };
  ptrace(PT_IO, pid, (caddr_t)&iod, 0);
  return iod.piod_len;
}

size_t PTraceRead(pid_t pid, void *buf, const void *addr, size_t len) {
  return ptracerw(PIOD_READ_D, pid, buf, (void *)addr, len);
}

size_t PTraceWrite(pid_t pid, void *addr, const void *buf, size_t len) {
  return ptracerw(PIOD_WRITE_D, pid, (void *)buf, addr, len);
}
