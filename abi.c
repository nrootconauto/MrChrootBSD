#include <assert.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/types.h>
/* clang-format off */
#include <sys/cdefs.h>
#include <machine/reg.h>
/* clang-format on */

#include "abi.h"
#include "ptrace.h"

#ifdef __x86_64__
#define Ones(x) ((1ul << x) - 1) // Ones(4) -> 0xF (0b1111)
#define Getregs(p, r) ptrace(PT_GETREGS, (p), (caddr_t)(r), 0)
#define Setregs(p, r) ptrace(PT_SETREGS, (p), (caddr_t)(r), 0)

int64_t ABIGetReturn(pid_t pid, bool *failed) {
  struct reg regs;
  Getregs(pid, &regs);
  if (failed)
    *failed = regs.r_rflags & 1; // Carry flag
  return regs.r_rax;
}

void ABISetReturn(pid_t pid, int64_t val, bool failed) {
  struct reg regs;
  Getregs(pid, &regs);
  regs.r_rdx = 0;
  regs.r_rax = val;
  if (failed)
    regs.r_rflags |= 1; // Carry flag
  else
    regs.r_rflags &= ~1ul;
  Setregs(pid, &regs);
}

void ABISetSyscall(pid_t pid, int64_t num) {
  struct reg regs;
  Getregs(pid, &regs);
  regs.r_rax = num;
  Setregs(pid, &regs);
}

// Quoth SysV ABI Fig 3.4
static size_t abi_off[] = {
    offsetof(struct reg, r_rdi), //
    offsetof(struct reg, r_rsi), //
    offsetof(struct reg, r_rdx), //
    offsetof(struct reg, r_rcx), //
    offsetof(struct reg, r_r8),  //
    offsetof(struct reg, r_r9),  //
};

int64_t ABIGetArg(pid_t pid, int64_t arg) {
  struct reg regs;
  Getregs(pid, &regs);
  if (arg <= 5) // reg args
    return *(int64_t *)((char *)&regs + abi_off[arg]);
  else {
    int64_t ret;
    uintptr_t argp = regs.r_rsp + 8 * (arg - 6);
    assert(8 == PTraceRead(pid, &ret, (void *)argp, 8));
    return ret;
  }
}

void ABISetArg(pid_t pid, int64_t arg, uint64_t val) {
  struct reg regs;
  Getregs(pid, &regs);
  if (arg <= 5) { // reg args
    *(uint64_t *)((char *)&regs + abi_off[arg]) = val;
    Setregs(pid, &regs);
  } else {
    uintptr_t argp = regs.r_rsp + 8 * (arg - 6);
    assert(8 == PTraceWrite(pid, (void *)argp, &val, 8));
  }
}
#else
#error Unsupported
#endif
