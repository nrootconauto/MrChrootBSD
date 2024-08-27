#include "abi.h"
#include "mrchroot.h"
#include "ptrace.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
/* clang-format off */
#include <kvm.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libprocstat.h>
#define class(x)                                                               \
  typedef struct x x;                                                          \
  struct x
static int ptrace2(int a,pid_t p,void *add ,int d) {
	int r=ptrace(a,p,add,d);
	return r;
}
#define ptrace ptrace2
class (CMountPoint) {
  CMountPoint *last, *next;
  char src_path[1024], dst_path[1024];
} mount_head, *root_mount;

class (CWaitEvent) {
	CWaitEvent *last,*next;
	int code;
	pid_t to,from;
	siginfo_t siginf;
} wait_events;
#define PIF_WAITING 1
#define PIF_PTRACE_FOLLOW_FORK 2
#define PIF_PTRACE_LWP_EVENTS 4
#define PIF_TRACE_ME 8 //"chrooted" Debugger wants first dibs on the first SIGTRAP
#define PIF_TRACE_ME2 16
#define PIF_EXITED 32 
#define PIF_TO_SCX_ONLY 64 
class (CProcInfo) {
  CProcInfo *last, *next;
  pid_t pid,parent,debugged_by;
  int wait_for_type,wait_for_id,wait_options;
  CMrChrootHackPtrs *hacks_array_ptr;
  int64_t flags;
  int ptrace_event_mask;
  struct ptrace_lwpinfo lwpinfo;
} proc_head;
/* clang-format on */
static void RemoveWaitEvent(CWaitEvent *);
static void RemoveProc(pid_t pid) {
  CProcInfo *cur, *next, *last;
  CWaitEvent *wev, *ev_next;
  for (cur = proc_head.next; cur != &proc_head; cur = cur->next) {
    if (pid == cur->pid) {
      last = cur->last;
      next = cur->next;
      next->last = last;
      last->next = next;
      free(cur);
      for (wev = wait_events.next; wev != &wait_events; wev = ev_next) {
        ev_next = wev->next;
        if (wev->to == pid)
          RemoveWaitEvent(wev);
      }
      return;
    }
  }
}
static char *StrMove(char *to, char *from) {
  int64_t len = strlen(from) + 1;
  return memmove(to, from, len);
}

static int64_t UnChrootPath(char *to, char *from) {
  char buf[1024], *cur = buf;
  CMountPoint *mp, *best = root_mount;
  int64_t trim, best_len = 0xffff, len;
  for (mp = mount_head.next; mp != &mount_head; mp = mp->next) {
    len = strlen(mp->dst_path);
    if (!strncmp(from, mp->dst_path, len)) {
      if (best_len < len) {
        best_len = len;
        best = mp;
      }
    }
  }

  trim = strlen(best->dst_path);
  *cur++ = '/';
  StrMove(cur, from + trim);
  if (to)
    strcpy(to, buf);
  return strlen(buf);
}
static int64_t GetProcCwd(char *to, pid_t pid) {
  unsigned cnt = 0;
  int64_t res_cnt = 0;
  char buf[1024];
  static struct procstat *ps;
  if (!ps)
    ps = procstat_open_sysctl();
  struct filestat_list *head;
  // See /usr/src/use.bin/procstat in FreeBSD
  struct filestat *fs;
  struct kinfo_proc *kprocs = procstat_getprocs(ps, KERN_PROC_PID, pid, &cnt);
  for (unsigned i = 0; i < cnt; i++) {
    head = procstat_getfiles(ps, kprocs, 0);
    STAILQ_FOREACH(fs, head, next) {
      if (fs->fs_path && fs->fs_uflags & PS_FST_UFLAG_CDIR) {
        res_cnt = UnChrootPath(buf, fs->fs_path);
        if (to)
          strcpy(to, buf);
        break;
      }
    }
    procstat_freefiles(ps, head);
  }
  procstat_freeprocs(ps, kprocs);
  return res_cnt;
}
static void PTraceRestoreBytes(pid_t pid, void *pt_ptr, void *backup,
                               size_t len) {
  assert(PTraceWrite(pid, pt_ptr, backup, len) == len);
}

static void PTraceWriteBytes(pid_t pid, void *pt_ptr, const void *st,
                             size_t len) {
  assert(PTraceWrite(pid, pt_ptr, st, len) == len);
}

#define declval(T) (*(T *)0ul)
#define Startswith(s, what) (!memcmp((s), (what), strlen(what)))
static CProcInfo *GetProcInfByPid(pid_t pid) {
  CProcInfo *cur;
  for (cur = proc_head.next; cur != &proc_head; cur = cur->next) {
    if (pid == cur->pid)
      return cur;
  }
  *(cur = malloc(sizeof *cur)) = (CProcInfo){.next = &proc_head,
                                             .last = proc_head.last,
                                             .pid = pid,
                                             .ptrace_event_mask = -1};
  return cur->last->next   //
         = cur->next->last //
         = cur;
}

static int64_t PidIsValid(pid_t pid) {
  CProcInfo *cur;
  for (cur = proc_head.next; cur != &proc_head; cur = cur->next) {
    if (pid == cur->pid)
      return 1;
  }
  return 0;
}

static void RemoveWaitEvent(CWaitEvent *ev) {
  CWaitEvent *last = ev->last;
  CWaitEvent *next = ev->next;
  if (last)
    last->next = next;
  if (next)
    next->last = last;
  free(ev);
}
static int64_t WaitEventPassesOptions(int what, int options) {
  if (options & WCONTINUED)
    if (WIFCONTINUED(what))
      return 1;
  if (options & WSTOPPED)
    if (WIFSTOPPED(what))
      return 1;
  if (options & WEXITED)
    if (WIFEXITED(what))
      return 1;
  if (options & WUNTRACED)
    if (WIFSTOPPED(what)) {
      return 1;
    }
  if (WIFSIGNALED(what))
    return 1;
  return 0;
}
static int64_t IsChildProc(pid_t child, pid_t parent) {
  if (!child || !parent)
    return 0;
  CProcInfo *pinf = GetProcInfByPid(parent);
  CProcInfo *cinf = GetProcInfByPid(child);
  if (!cinf || !pinf)
    return 0;
  if (cinf->parent == parent)
    return 1;
  return IsChildProc(cinf->parent, parent);
}
static void InterceptPtrace(pid_t pid) {
  int req = ABIGetArg(pid, 0);
  pid_t who = ABIGetArg(pid, 1);
  void *addr = (void *)ABIGetArg(pid, 2);
  int64_t data = ABIGetArg(pid, 3), ret = 0;
  CProcInfo *pinf;
  int failed = 0;
  GetProcInfByPid(who)->debugged_by = pid;
  switch (req) {
  case PT_TRACE_ME:
    pinf = GetProcInfByPid(pid);
    ABISetSyscall(
        pid, 20); // Run *getpid* instread of ptrace(dont run ptrace on ptrace)
    ptrace(PT_TO_SCX, pid, (caddr_t)1, 0);
    waitpid(pid, NULL, 0);
    ABISetReturn(pid, 0, NULL);
    pinf->flags |= PIF_TRACE_ME;
    pinf->ptrace_event_mask = PL_FLAG_EXEC;
    break;
  case PT_CONTINUE:
  // cool beans
  // Dont allow child process to use its ptrace,use MrChrootBSD's ptrace
  case PT_READ_I:
  case PT_READ_D:
  case PT_WRITE_I:
  case PT_WRITE_D:
    goto use_host_ptrace;
  case PT_IO: {
    struct ptrace_io_desc iod, iod2;
    data = sizeof(iod);
    PTraceRead(pid, &iod, addr, data);
    iod2 = iod;
    size_t len;
    char *buffer = calloc(1, iod2.piod_len);
    iod2.piod_addr = buffer;
    switch (iod.piod_op) {
    case PIOD_WRITE_I:
    case PIOD_WRITE_D:
      PTraceRead(pid, buffer, iod.piod_addr, iod.piod_len);
      ptrace(PT_IO, who, &iod2, sizeof(iod2));
      break;
    case PIOD_READ_I:
    case PIOD_READ_D:
      ptrace(PT_IO, who, &iod2, sizeof(iod2));
      PTraceWrite(pid, iod.piod_addr, buffer, iod.piod_len);
      break;
    }
    // Restore original
    iod2.piod_addr = iod.piod_addr;
    PTraceWrite(pid, addr, &iod2, sizeof(iod));
    free(buffer);
    goto intercept;
  }
  case PT_STEP:
  case PT_KILL:
  case PT_ATTACH:
  case PT_DETACH:
    goto use_host_ptrace;
  case PT_GETREGSET:
  case PT_SETREGSET:
    printf("imp layer\n");
    ret = -1;
    failed = 1;
    break;
  case PT_GETFSBASE:
  case PT_GETGSBASE:
  case PT_GETREGS:
  case PT_GETFPREGS:
  case PT_GETDBREGS:
  case PT_GETXSTATE_INFO:
  case PT_GETXSTATE:
  case PT_LWPINFO: {
  read_style:;
    if (req == PT_GETREGS)
      data = sizeof(struct reg);
    else if (req == PT_GETFPREGS)
      data = sizeof(struct fpreg);
    else if (req == PT_GETDBREGS)
      data = sizeof(struct dbreg);
    else if (req == PT_GETXSTATE_INFO)
      data = sizeof(struct ptrace_xstate_info);
    else if (req == PT_GETFSBASE)
      data = sizeof(unsigned long);
    else if (req == PT_GETGSBASE)
      data = sizeof(unsigned long);
    // Write nto poo poo tasks addres space
    void *dumb = malloc(data);
    ret = ptrace(req, who, dumb, data);
    if (ret == -1) {
      ret = -errno;
      failed = 1;
    }
    PTraceWriteBytes(pid, addr, dumb, data);
    free(dumb);
    goto intercept;
  }
  case PT_GETNUMLWPS:
    goto use_host_ptrace;
  case PT_GETLWPLIST:
    goto read_style;
  case PT_SETSTEP:
  case PT_CLEARSTEP:
  case PT_SUSPEND:
  case PT_RESUME:
  case PT_TO_SCE:
  case PT_TO_SCX:
  case PT_SYSCALL:
    goto use_host_ptrace;
  case PT_GET_SC_ARGS:
  case PT_GET_SC_RET:
    goto read_style;
  case PT_VM_TIMESTAMP:
  case PT_VM_ENTRY:
    printf("unimpBM");
    goto use_host_ptrace;
    break;
  case PT_COREDUMP:
  case PT_SC_REMOTE:
    goto read_style;
  // X86 specific
  // case PT_GETXMMREGS:
  // case PT_GETXSTATE_INFO:
  // case PT_SETXMMREGS:
  case PT_SETXSTATE:
  case PT_SETREGS:
  case PT_SETFPREGS:
  case PT_SETDBREGS:
  case PT_SETGSBASE:
  case PT_SETFSBASE: {
  write_style:;
    if (req == PT_SETREGS)
      data = sizeof(struct reg);
    else if (req == PT_SETFPREGS)
      data = sizeof(struct fpreg);
    else if (req == PT_SETDBREGS)
      data = sizeof(struct dbreg);
    else if (req == PT_SETFSBASE)
      data = sizeof(unsigned long);
    else if (req == PT_SETGSBASE)
      data = sizeof(unsigned long);
    // Read from poo poo tasks addres space
    void *dumb = malloc(data);
    PTraceRead(pid, dumb, addr, data);
    ret = ptrace(req, who, dumb, data);
    if (ret < 0) {
      failed = 1;
      ret = -errno;
    }
    free(dumb);
    goto intercept;
  }
  default:
  use_host_ptrace:
    if (req == PT_READ_D || req == PT_READ_I)
      ret = ptrace(req, who, addr, data);
    else {
      ret = ptrace(req, who, addr, data);
    }
  intercept:
    ABISetSyscall(
        pid, 20); // Run *getpid* instread of ptrace(dont run ptrace on ptrace)
    ptrace(PT_TO_SCX, pid, (caddr_t)1, (SIGSTOP));
    waitpid(pid, NULL, 0);
    // I ran *getpid* instead of ptrace,that means RAX has pid
    pinf = GetProcInfByPid(ABIGetReturn(pid, NULL));
    ABISetReturn(pid, ret, failed);
    break;
  case PT_LWP_EVENTS:
    GetProcInfByPid(who)->flags |= PIF_PTRACE_LWP_EVENTS;
    goto intercept;
    break;
  case PT_FOLLOW_FORK: {
    pinf = GetProcInfByPid(who);
    pinf->flags |= PIF_PTRACE_FOLLOW_FORK;
    pinf->debugged_by = pid;
    goto intercept;
  } break;
  case PT_GET_EVENT_MASK: {
    pinf = GetProcInfByPid(who);
    ret = ptrace(PT_WRITE_D, pid, addr, pinf->ptrace_event_mask);
    goto intercept;
  } break;
  case PT_SET_EVENT_MASK: {
    pinf = GetProcInfByPid(who);
    pinf->ptrace_event_mask = ptrace(PT_READ_D, pid, (caddr_t)addr, (int)addr);
    goto intercept;
  } break;
  }
}
static CWaitEvent *EventForWait(pid_t pid, pid_t who, int _idtype) {
  CWaitEvent *wev;
  for (wev = wait_events.next; wev != &wait_events; wev = wev->next) {
    if (wev->to == pid) {
      if (_idtype == 0) {
        if (who == -1) { // Any child
          return wev;
        }
        if (who == -1) { // Any child with same gpid
          if (getpgid(wev->from) == getpgid(wev->to))
            return wev;
        }
        if (who > 0) {
          if (wev->from == who)
            return wev;
        }
        if (who < -1) {
          if (-wev->from == getpgid(who))
            return wev;
        }
      }
      if (_idtype == P_PID) {
        if (who == 0) {
          if (getpgid(wev->to) == getpgid(wev->from))
            return wev;
        } else if (wev->from == who)
          return wev;
      }
      if (_idtype == P_PGID) {
        if (who == 0) {
          if (getpgid(wev->to) == getpgid(wev->from))
            return wev;
        } else if (getpgid(wev->from) == who)
          return wev;
      }
      if (_idtype == P_ALL) {
        return wev;
      }
    }
  }
  return NULL;
}
static void DiscardWait(pid_t pid, pid_t discard) {
  bool failed;
  int64_t oldr = ABIGetReturn(pid, &failed);
  int64_t args4[4] = {discard, 0, 0, 0};
  struct ptrace_sc_remote dummy;
  dummy.pscr_args = &args4;
  dummy.pscr_nargs = 4;
  dummy.pscr_syscall = 7;
  assert(0 == ptrace(PT_SC_REMOTE, pid, &dummy, sizeof(dummy)));
  waitpid(pid, NULL, 0);
  ABISetReturn(pid, oldr, failed);
}
static void UpdateWaits() {
  CProcInfo *cur, *cur2;
  CWaitEvent *wev;
  struct ptrace_lwpinfo ptinf;
  struct ptrace_lwpinfo inf;
  int *write_code_to, who, wflags;
  struct ptrace_sc_remote dummy;
  int64_t args4[4];
  for (cur = proc_head.last; cur != &proc_head; cur = cur->last) {
    if (cur->flags & PIF_WAITING) {
      ptrace(PT_LWPINFO, cur->pid, &inf, sizeof(inf));
      // A safe-place to run PT_SC_REMOTE  is at syscall exit.
      // Keep values before our "dumb" syscall
      write_code_to = (int *)ABIGetArg(cur->pid, 1);
      wflags = (int)ABIGetArg(cur->pid, 2);
      who = (int)ABIGetArg(cur->pid, 0);
      args4[0] = who;
      args4[1] = (int64_t)write_code_to;
      args4[2] = wflags | WNOHANG | WNOWAIT;
      args4[3] = ABIGetArg(cur->pid, 3);
      if (inf.pl_flags & PL_FLAG_SCE) {
        // run a dummy syscall
        ABISetSyscall(cur->pid, 20);
        ptrace(PT_TO_SCX, cur->pid, (caddr_t)1, 0);
        waitpid(cur->pid, NULL, 0);
        ABISetReturn(cur->pid, 0, 0);
      }
    wait4:;
      // Run a dummy WAIT with WNOHANG to check if a signal has come
      // I have to insert "PTRACE" signals too
      dummy.pscr_args = &args4;
      dummy.pscr_nargs = 4;
      dummy.pscr_syscall = 7;
      assert(0 == ptrace(PT_SC_REMOTE, cur->pid, &dummy, sizeof(dummy)));
      waitpid(cur->pid, NULL, 0);
      ABISetArg(cur->pid, 0, args4[0]);
      ABISetArg(cur->pid, 1, args4[1]);
      ABISetArg(cur->pid, 2, wflags);
      ABISetArg(cur->pid, 3, args4[3]);
      if (wev = EventForWait(cur->pid, who, 0)) {
        ptrace(PT_WRITE_D, cur->pid, write_code_to, wev->code);
        ABISetReturn(cur->pid, wev->from, 0);
        RemoveWaitEvent(wev);
        cur->flags &= ~PIF_WAITING;
        ptrace(PT_TO_SCE, cur->pid, (caddr_t)1, 0);
        goto next;
      }
      if (dummy.pscr_ret.sr_error != 0) {
        // Syscalls return -errcode on error
        // PT_SC_REMOTE deosnt put error in pscr_ret.sr_retval
        cur->flags &= ~PIF_WAITING;
        ABISetReturn(cur->pid, -dummy.pscr_ret.sr_error, 1);
        ptrace(PT_TO_SCE, cur->pid, (caddr_t)1, 0);
      say_got:
        if (write_code_to) {
          int code = ptrace(PT_READ_D, cur->pid, write_code_to, 0);
        }
        goto next;
      }
      // Restore our regs?
      if (dummy.pscr_ret.sr_retval[0] == -1) {
        ABISetReturn(cur->pid, dummy.pscr_ret.sr_retval[0],
                     dummy.pscr_ret.sr_error);
        // something went wrong
        cur->flags &= ~PIF_WAITING;
        ptrace(PT_TO_SCE, cur->pid, (caddr_t)1, 0);
        goto say_got;
        goto next;
      } else if (dummy.pscr_ret.sr_retval[0] != 0) {
        DiscardWait(cur->pid,
                    dummy.pscr_ret.sr_retval[0]); // EARILER I USED WNOWAIT
        // Got a valid pid?
        cur->flags &= ~PIF_WAITING;
        ABISetReturn(cur->pid, dummy.pscr_ret.sr_retval[0],
                     dummy.pscr_ret.sr_error);
        ptrace(PT_TO_SCE, cur->pid, (caddr_t)1, 0);
        goto say_got;
        goto next;
      }
      // if WNOHANG was set,return as usale

      if (wflags & WNOHANG) {
        cur->flags &= ~PIF_WAITING;
        ABISetReturn(cur->pid, 0, 0);
        goto next;
      }
    }
  next:;
  }
}
static void DelegatePtraceEvent(pid_t to, pid_t who, int code) {
  if (to != who) {
    CWaitEvent *ev = calloc(1, sizeof(CWaitEvent)), *tmp;
    ev->to = to;
    ev->from = who;
    ev->code = code;
    ev->last = wait_events.last;
    ev->next = &wait_events;
    ev->next->last = ev;
    ev->last->next = ev;
  }
  UpdateWaits();
}
static void InterceptWait(pid_t pid, int wait_for_type, int wait_for_id) {
  CProcInfo *inf = GetProcInfByPid(pid);
  inf->flags |= PIF_WAITING;
  UpdateWaits();
  return;
}

static int64_t NormailizePath(char *to, const char *path) {
  int64_t idx;
  char result[1024];
  strcpy(result, path);
  for (idx = 0; result[idx]; idx++) {
  again:
    if (result[idx] == '/') {
      if (result[idx + 1] == '/') {
        StrMove(&result[idx], &result[idx + 1]);
        goto again;
      } else if (result[idx + 1] == '.') {
        if (!result[idx + 2] || result[idx + 2] == '/') {
          StrMove(&result[idx + 1], &result[idx + 2]);
          goto again;
        }
      }
    }
  }
  if (!*result)
    strcpy(result, "/");
  if (to)
    strcpy(to, result);
  return strlen(result);
}

static int64_t GetChrootedPath(char *to, pid_t pid, const char *path) {
  int64_t idx;
  size_t max_match = 0, len;
  char result[1024];
  char s[1024], *cur = s;
  // CProcInfo *pi = GetProcInfByPid(pid);
  CMountPoint *mp, *choose;
  struct ptrace_lwpinfo inf;
  ptrace(PT_LWPINFO, pid, (caddr_t)&inf, sizeof inf);
  if (*path == '/')
    strcpy(result, "/");
  else {
    GetProcCwd(result, pid);
    strcat(result, "/");
  }
  strcat(result, path);
  NormailizePath(result, result);
  for (mp = mount_head.next; mp != &mount_head; mp = mp->next) {
    // FORCE it to be normal(failsafe)
    NormailizePath(mp->src_path, mp->src_path);
    if (max_match < (len = strlen(mp->src_path)))
      if (Startswith(result, mp->src_path)) {
        max_match = len;
        choose = mp;
      }
  }
  if (!choose) {
    fprintf(stderr, "Unable to find mount point for \"%s\"\n", result);
    exit(1);
  }
  mp = choose;
  cur = stpcpy(cur, mp->dst_path);
  *cur++ = '/';
  cur = stpcpy(cur, result + strlen(mp->src_path));
  NormailizePath(s, s);
  idx = strlen(s);
  if (idx)
    if (s[idx - 1] == '/')
      s[idx - 1] = 0;
  if (to)
    strcpy(to, s);
  return strlen(s);
}

static ptrdiff_t ReadPTraceString(char *to, pid_t pid, char *pt_ptr) {
  char *al_ptr = (char *)((uintptr_t)(pt_ptr + 255) & -256), *cur, *nul;
  size_t ret = 0;
  ptrdiff_t diff;
  if ((diff = al_ptr - pt_ptr)) {
    char buf[diff];
    assert(PTraceRead(pid, buf, pt_ptr, diff) == (size_t)diff);
    if ((nul = memchr(buf, 0, diff))) {
      memcpy(to, buf, nul - buf + 1);
      return nul - buf;
    }
    memcpy(to, buf, diff);
    ret += diff;
    to += diff;
  }
  cur = al_ptr;
  char s[256];
  size_t readb;
  while (true) {
    readb = PTraceRead(pid, s, cur, 256);
    if ((nul = memchr(s, 0, readb))) {
      memcpy(to, s, nul - s + 1);
      return ret + nul - s;
    }
    to += readb;
    cur += readb;
    ret += readb;
  }
}
static size_t WritePTraceString(void *backup, pid_t pid, void *pt_ptr,
                                char const *st) {
  size_t len = strlen(st) + 1;
  if (backup)
    assert(PTraceRead(pid, backup, pt_ptr, len) == len);
  assert(PTraceWrite(pid, pt_ptr, st, len) == len);
  return len;
}

#define INTERCEPT_FILE1(pid, arg)                                              \
  char backupstr[1024];                                                        \
  char have_str[1024], chroot[1023];                                           \
  int64_t backup_len;                                                          \
  void *orig_ptr;                                                              \
  orig_ptr = (void *)ABIGetArg(pid, arg);                                      \
  ReadPTraceString(have_str, pid, orig_ptr);                                   \
  GetChrootedPath(chroot, pid, have_str);                                      \
  backup_len = WritePTraceString(backupstr, pid, orig_ptr, chroot);            \
  ptrace(PT_TO_SCX, pid, (void *)1, 0);                                        \
  waitpid(pid, NULL, 0);                                                       \
  PTraceRestoreBytes(pid, orig_ptr, backupstr, backup_len);

#define INTERCEPT_FILE1_ONLY_ABS(pid, arg)                                     \
  char backupstr[1024];                                                        \
  char have_str[1024], chroot[1023];                                           \
  int64_t backup_len;                                                          \
  void *orig_ptr;                                                              \
  orig_ptr = (void *)ABIGetArg(pid, arg);                                      \
  ReadPTraceString(have_str, pid, orig_ptr);                                   \
  if (have_str[0] == '/') {                                                    \
    GetChrootedPath(chroot, pid, have_str);                                    \
    backup_len = WritePTraceString(backupstr, pid, orig_ptr, chroot);          \
    ptrace(PT_TO_SCX, pid, (void *)1ul, 0);                                    \
    waitpid(pid, NULL, 0);                                                     \
    PTraceRestoreBytes(pid, orig_ptr, backupstr, backup_len);                  \
  } else {                                                                     \
    ptrace(PT_TO_SCX, pid, (void *)1ul, 0);                                    \
    waitpid(pid, NULL, 0);                                                     \
  }

static void InterceptRealPathAt(pid_t pid) {
  char have_str[1024], chroot[1023];
  void *orig_ptr, *to_ptr;
  orig_ptr = (void *)ABIGetArg(pid, 1);
  to_ptr = (void *)ABIGetArg(pid, 2);
  ReadPTraceString(have_str, pid, orig_ptr);
  GetChrootedPath(chroot, pid, have_str);
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, NULL, 0);
  UnChrootPath(chroot, chroot);
  PTraceWriteBytes(pid, to_ptr, chroot, strlen(chroot) + 1);
  ABISetReturn(pid, 0, 0);
}

static void InterceptAccess(pid_t pid) { INTERCEPT_FILE1(pid, 0); }

static void InterceptOpen(pid_t pid) { INTERCEPT_FILE1(pid, 0); }

static bool CheckShebang(char *chrooted_name, char *prog_name_to) {
  int fd = open(chrooted_name, O_RDONLY);
  if (-1 == fd)
    return false;
  char buf[0x100], *ptr;
  ssize_t readb = read(fd, buf, 0xFF);
  close(fd);
  if (readb < 2)
    return false;
  if (!memcmp(buf, "#!", 2)) {
    buf[readb] = 0;
    if (!(ptr = strchr(buf + 2, '\n')))
      return false;
    if (prog_name_to) {
      ptr = mempcpy(prog_name_to, buf + 2, ptr - (buf + 2));
      *ptr = 0;
    }
    return true;
  }
  return false;
}

static char *SkipWhitespace(char *p) {
  while (*p && isblank((unsigned char)*p))
    p++;
  return p;
}

static void *PTraceReadPtr(pid_t pid, void *at) {
  void *ret;
  assert(PTraceRead(pid, &ret, at, 8) == 8);
  return ret;
}

static void PTraceWritePtr(pid_t pid, void *at, void *ptr) {
  assert(PTraceWrite(pid, at, &ptr, 8) == 8);
}
static void *GetHackDataAreaForPid(pid_t pid) {
  CProcInfo *pinf = GetProcInfByPid(pid);
  return PTraceReadPtr(pid, &pinf->hacks_array_ptr->data_zone);
}
// Returns end of written data
static char *RewriteEnv(pid_t pid, char **prog_env, char *data_ptr) {
  int64_t idx, idx2, argc = 0;
  char *arg;
  char val[4048];
  char chrooted[4048], orig[4048], final[4048];
  for (idx = 0; arg = PTraceReadPtr(pid, prog_env + idx); idx++)
    argc++;
  char *new_env_ptrs[argc];
  for (idx = 0; arg = PTraceReadPtr(pid, prog_env + idx); idx++) {
#define LD_LIBRARY_PATH_EQ "LD_LIBRARY_PATH="
    ReadPTraceString(val, pid, arg);
    if (!strncmp(LD_LIBRARY_PATH_EQ, val, strlen(LD_LIBRARY_PATH_EQ))) {
      strcpy(final, LD_LIBRARY_PATH_EQ);
      char *start = val + strlen(LD_LIBRARY_PATH_EQ), *end;
    again:
      end = start;
      while (*end && *end != ':')
        end++;
      orig[0] = 0;
      idx2 = 0;
      while (start != end) {
        orig[idx2++] = *start++;
      }
      orig[idx2] = 0;
      GetChrootedPath(chrooted, pid, orig);
      strcpy(final + strlen(final), chrooted);
      if (*end == ':') {
        strcpy(final + strlen(final), ":");
        start = end + 1;
        goto again;
      }
      WritePTraceString(NULL, pid, data_ptr, final);
      new_env_ptrs[idx] = data_ptr;
      PTraceWritePtr(pid, new_env_ptrs[idx], prog_env + idx);
      data_ptr += strlen(final) + 1;
    } else {
      new_env_ptrs[idx] = arg;
    }
  }
  return data_ptr;
}
static void InterceptExecve(pid_t pid) {
  char have_str[1024], chroot[1024], backup[1024], poop_ant[1024];
  char *orig_ptr, **argv, **env;
  char *ptr, *ptr2, *command, *argument;
  int64_t fd, args[3], bulen, extra_args = 0;
  struct ptrace_sc_remote rmt;
  CProcInfo *pinf = GetProcInfByPid(pid);
  orig_ptr = (void *)ABIGetArg(pid, 0);
  argv = (void *)ABIGetArg(pid, 1);
  env = (void *)ABIGetArg(pid, 2);
  ReadPTraceString(have_str, pid, orig_ptr);
  GetChrootedPath(chroot, pid, have_str);
  memset(poop_ant, 0, sizeof(poop_ant));
  if (!CheckShebang(chroot, poop_ant)) {
    char *tmp1, *tmp2;
    // exeve(open(chrooted),argv,env)
    ABISetSyscall(pid, 5); // iopen
    ABISetArg(pid, 1, O_EXEC);
    ReadPTraceString(poop_ant, pid, orig_ptr);
    GetChrootedPath(chroot, pid, poop_ant);
    bulen = WritePTraceString(backup, pid, orig_ptr, chroot);
    ptrace(PT_TO_SCX, pid, (void *)1, 0);
    waitpid(pid, NULL, 0);
    PTraceRestoreBytes(pid, orig_ptr, backup, bulen);
    args[0] = ABIGetReturn(pid, NULL);
    args[1] = (int64_t)argv;
    args[2] = (int64_t)env;
    rmt.pscr_syscall = 492;
    rmt.pscr_nargs = 3;
    rmt.pscr_args = args;
    RewriteEnv(pid, env, GetHackDataAreaForPid(pid));
    ptrace(PT_SC_REMOTE, pid, (caddr_t)&rmt, sizeof rmt);
  } else {
    char *extra_arg_ptrs[256];
    // fexecve(open("interrepret name"),argv,env)
    command = SkipWhitespace(poop_ant);
    ptr2 = command;
    while (*ptr2 && !isblank(*ptr2))
      ptr2++;
    *ptr2++ = 0;
    GetChrootedPath(chroot, pid, command);
    ABISetSyscall(pid, 5);
    ABISetArg(pid, 1, O_EXEC);
    bulen = WritePTraceString(backup, pid, orig_ptr, chroot);
    ptrace(PT_TO_SCX, pid, (void *)1, 0);
    waitpid(pid, NULL, 0);

    PTraceRestoreBytes(pid, orig_ptr, backup, bulen);
    // Insert the pointer to the command name before argv(I will dump the
    // name to NULL,it doesnt matter as we will change the program image at
    // fexecve)
    ptr = GetHackDataAreaForPid(pid);
    extra_args = 0;
    WritePTraceString(NULL, pid, ptr, command);
    extra_arg_ptrs[extra_args++] = ptr;
    ptr += strlen(command) + 1;
    while (*ptr2) {
      ptr2 = SkipWhitespace(ptr2);
      argument = ptr2;
      while (*ptr2 && !isblank((unsigned char)*ptr2))
        ptr2++;
      *ptr2++ = 0;
      extra_arg_ptrs[extra_args++] = ptr;
      WritePTraceString(NULL, pid, ptr, argument);
      ptr += strlen(argument) + 1;
    }

    // IF we have '#! /bin/tcsh -xv' in ./poop.sh, do
    // argv[0] = bin/tcsh
    // argv[1] = -xv
    // argv[2] = ./poop.s
    // argv[...] = ...

    // Put command name here
    WritePTraceString(NULL, pid, ptr, have_str);
    extra_arg_ptrs[extra_args++] = ptr;
    ptr += strlen(have_str) + 1;

    argv -= extra_args;

    for (fd = 0; fd != extra_args; fd++) {
      PTraceWritePtr(pid, argv + fd, extra_arg_ptrs[fd]);
      ReadPTraceString(have_str, pid, extra_arg_ptrs[fd]);
    }

    // The first argument to the argv is the program name,but we delegated
    // it to the interrepter REMOVE THE FIRST ARGUMENT AS IT IS UNECESARY
    while (PTraceReadPtr(pid, argv + fd)) {
      PTraceWritePtr(pid, argv + fd, PTraceReadPtr(pid, argv + fd + 1));
      fd++;
    }

    args[0] = ABIGetReturn(pid, NULL);
    args[1] = (int64_t)argv;
    args[2] = (int64_t)env;
    rmt.pscr_syscall = 492;
    rmt.pscr_nargs = 3;
    rmt.pscr_args = args;
    RewriteEnv(pid, env, ptr);
    ptrace(PT_SC_REMOTE, pid, (caddr_t)&rmt, sizeof rmt);
  }
}

static void InterceptReadlink(pid_t pid) {
  char new_path[1024], got_path[1024], backup[1024];
  char rlbuf[1024];
  int64_t backup_len, r, buf_len = ABIGetArg(pid, 2);
  void *orig_ptr = (void *)ABIGetArg(pid, 0),
       *buf_ptr = (void *)ABIGetArg(pid, 1);
  ReadPTraceString(got_path, pid, orig_ptr);
  GetChrootedPath(new_path, pid, got_path);
  backup_len = WritePTraceString(backup, pid, orig_ptr, new_path);
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, NULL, 0);
  PTraceRestoreBytes(pid, orig_ptr, backup, backup_len);

  r = readlink(new_path, rlbuf, 1024);
  UnChrootPath(rlbuf, new_path);
  if (r < 0) {
    ABISetReturn(pid, r, 1);
  } else {
    r = strlen(rlbuf);
    PTraceWriteBytes(pid, buf_ptr, rlbuf, r > buf_len ? buf_len : r + 1);
    ABISetReturn(pid, r, 0);
  }
}

static void InterceptReadlinkAt(pid_t pid) {
  char new_path[1024], got_path[1024], backup[1024];
  char rlbuf[1024];
  int64_t backup_len, buf_len = ABIGetArg(pid, 3), r;
  void *orig_ptr = (void *)ABIGetArg(pid, 1),
       *buf_ptr = (void *)ABIGetArg(pid, 2);
  ReadPTraceString(got_path, pid, orig_ptr);
  if (*got_path == '/') {
    GetChrootedPath(new_path, pid, got_path);
    backup_len = WritePTraceString(backup, pid, orig_ptr, new_path);
    ptrace(PT_TO_SCX, pid, (void *)1, 0);
    waitpid(pid, NULL, 0);
    PTraceRestoreBytes(pid, orig_ptr, backup, backup_len);
  } else {
    ptrace(PT_TO_SCX, pid, (void *)1, 0);
    waitpid(pid, NULL, 0);
    ReadPTraceString(new_path, pid, buf_ptr);
  }
  r = readlink(new_path, rlbuf, 1024);
  if (r < 0)
    ABISetReturn(pid, r, 1);
  else {
    UnChrootPath(rlbuf, new_path);
    r = strlen(rlbuf);
    PTraceWriteBytes(pid, buf_ptr, rlbuf, r > buf_len ? buf_len : r + 1);
    ABISetReturn(pid, r, 0);
  }
}

#define INTERCEPT_FILE2(pid, arg1, arg2)                                       \
  char backup1[1024], chroot1[1024], got1[1024];                               \
  char backup2[1024], chroot2[1024], got2[1024];                               \
  void *orig_ptr1 = (void *)ABIGetArg(pid, arg1);                              \
  void *orig_ptr2 = (void *)ABIGetArg(pid, arg2);                              \
  char *dumb_ptr =                                                             \
      orig_ptr1; /*write 2 strings to  1 pointer in case orig_ptr1/orig_ptr2   \
                    overlap(chrooted strings are larger than originals)*/      \
  int64_t backup_len1, backup_len2;                                            \
  ReadPTraceString(got1, pid, orig_ptr1);                                      \
  ReadPTraceString(got2, pid, orig_ptr2);                                      \
  GetChrootedPath(chroot1, pid, got1);                                         \
  GetChrootedPath(chroot2, pid, got2);                                         \
  /*                                                                           \
  //[chroot1\0chroot2\0]                                                       \
  //          ^                                                                \
  //          |                                                                \
  //          + Arg1 is here*/                                                 \
  dumb_ptr = orig_ptr1;                                                        \
  backup_len1 = WritePTraceString(backup1, pid, orig_ptr1, chroot1);           \
  dumb_ptr += backup_len1;                                                     \
  backup_len2 = WritePTraceString(backup2, pid, dumb_ptr, chroot2);            \
  ABISetArg(pid, 1, (int64_t)dumb_ptr); /*Re-assign poo poo address*/          \
  ptrace(PT_TO_SCX, pid, (void *)1, 0);                                        \
  waitpid(pid, NULL, 0);                                                       \
  PTraceRestoreBytes(pid, orig_ptr1, backup1, backup_len1);                    \
  PTraceRestoreBytes(pid, dumb_ptr, backup2, backup_len2);

static void InterceptLink(pid_t pid) { INTERCEPT_FILE2(pid, 0, 1); }

static void InterceptUnlink(pid_t pid) { INTERCEPT_FILE1(pid, 0); }

static void InterceptShmRename(pid_t pid) { INTERCEPT_FILE2(pid, 0, 1); }

static void InterceptChdir(pid_t pid) {
  char backupstr[1024];
  char have_str[1024], chroot[1023];
  int64_t backup_len;
  void *orig_ptr;
  orig_ptr = (void *)ABIGetArg(pid, 0);
  ReadPTraceString(have_str, pid, orig_ptr);
  GetChrootedPath(chroot, pid, have_str);
  backup_len = WritePTraceString(backupstr, pid, orig_ptr, chroot);
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, NULL, 0);
  PTraceRestoreBytes(pid, orig_ptr, backupstr, backup_len);
}

static void Intercept__Getcwd(pid_t pid) {
  int64_t olen, cap;
  void *orig_ptr;
  char cwd[1024];
  olen = GetProcCwd(cwd, pid);
  orig_ptr = (void *)ABIGetArg(pid, 0);
  cap = ABIGetArg(pid, 1);
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, NULL, 0);
  PTraceWriteBytes(pid, orig_ptr, cwd, cap > olen + 1 ? olen + 1 : cap);
  ABISetReturn(pid, 0, 0);
}

static void InterceptMount(pid_t pid) {
  (void)pid;
  // TODO
}

static void InterceptUnmount(pid_t pid) {
  (void)pid;
  // TODO
}

static void InterceptNmount(pid_t pid) {
  (void)pid;
  // TODO
}

static void InterceptAccessShmUnlink(pid_t pid) { INTERCEPT_FILE1(pid, 0); }

static void InterceptAccessTruncate(pid_t pid) { INTERCEPT_FILE1(pid, 0); }

static void InterceptFstat(pid_t pid) {
  // makes the file look like it was made by root (TODO enable/disable this
  // from command line)
  uint8_t *ptr = (void *)ABIGetArg(pid, 1);
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, NULL, 0);
#define W(p, T, m)                                                             \
  PTraceWrite(pid, p + offsetof(T, m), &(size_t){0}, sizeof declval(T).m)
  W(ptr, struct stat, st_uid);
  W(ptr, struct stat, st_gid);
}

static void InterceptFhstat(pid_t pid) {
  // makes the file look like it was made by root (TODO enable/disable this
  // from command line)
  char *ptr = (void *)ABIGetArg(pid, 1);
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, NULL, 0);
  W(ptr, struct stat, st_uid);
  W(ptr, struct stat, st_gid);
}

static void InterceptFstatat(pid_t pid) {
  // makes the file look like it was made by root (TODO enable/disable this
  // from command line)
  char *ptr = (void *)ABIGetArg(pid, 2);
  INTERCEPT_FILE1_ONLY_ABS(pid, 1);
  W(ptr, struct stat, st_uid);
  W(ptr, struct stat, st_gid);
}
#undef W

static void FakeGroup(pid_t pid) {
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, 0, 0);
  ABISetReturn(pid, 0, 0);
}

static CMountPoint *AddMountPoint(const char *dst, const char *src) {
  CMountPoint *mp = malloc(sizeof *mp);
  strcpy(mp->src_path, src);
  realpath(dst, mp->dst_path);
  mp->next = mount_head.next;
  mp->last = &mount_head;
  mp->next->last = mp;
  mp->last->next = mp;
  return mp;
}
static void FakeUser(pid_t pid) {
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, 0, 0);
  ABISetReturn(pid, 0, 0);
}

// Fakes a succeffusl return
static void FakeSuccess(pid_t pid) {
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, 0, 0);
  ABISetReturn(pid, 0, 0);
}

int main(int argc, const char **argv, const char **env) {
  pid_t pid, pid2;
  int64_t idx;
  char chroot_bin[1024];
  // CProcInfo *pnext, *plast;
  if (argc < 3) {
    fprintf(stderr, "Usage %s [chroot] [shell] ...",
            argc > 0 ? argv[0] : "slim_jail");
    return 1;
  }
  proc_head.last = &proc_head;
  proc_head.next = &proc_head;

  mount_head.last = &mount_head;
  mount_head.next = &mount_head;

  wait_events.last = &wait_events;
  wait_events.next = &wait_events;

  root_mount = AddMountPoint(argv[1], "/");
  AddMountPoint("/dev", "/dev");
  AddMountPoint("/proc", "/proc");

  if ((pid = fork())) {
    int cond;
    while ((pid2 = waitpid(-1, &cond,
                           WUNTRACED | WEXITED | WTRAPPED | WSTOPPED |
                               WCONTINUED))) {
      /*printf("SIG:%d,%d\n",pid2,WTERMSIG(cond));*/
      if (WIFEXITED(cond) && pid2 == pid)
        exit(0);
      struct ptrace_lwpinfo inf;
      CProcInfo *pinf = GetProcInfByPid(pid2);
      ptrace(PT_LWPINFO, pid2, (caddr_t)&inf, sizeof inf);
      ptrace(PT_FOLLOW_FORK, pid2, NULL, 1);
      if (WIFEXITED(cond)) {
        DelegatePtraceEvent(pinf->parent, pid2, cond);
        pid_t par = pinf->parent;
        pinf->flags |= PIF_EXITED;
        RemoveProc(pid2);
        continue;
      } else if (WIFSIGNALED(cond)) {
        if (1) {
          DelegatePtraceEvent(pinf->debugged_by, pid2, cond);
          if (pinf->debugged_by) {
          } else {
            ptrace(PT_CONTINUE, pid2, (void *)1, 0);
            RemoveProc(pid2);
          }
          UpdateWaits();
          continue;
        }
      }
      // Nested ptrace,delegate poo poo sauce to the "simulated" ptrace if
      // we are being debugged;
      {
        CProcInfo *pinf2;
        if (pinf->debugged_by || (pinf->flags & PIF_TRACE_ME)) {
          pid_t to = pinf->debugged_by;
          if (!to)
            to = pinf->parent;
          if (pinf->ptrace_event_mask &
              (inf.pl_flags & ~(PL_FLAG_SCE | PL_FLAG_SCX))) {
          send_out:;
            DelegatePtraceEvent(to, pid2, cond);
            kill(to, SIGCHLD);
            // Heres the DEAL.PT_TRACE_ME sets the PTRACE_EXEC flag in the
            // ptrace state(not reset when used)
            UpdateWaits();
            continue;
          }
        }
      }
    normal:
      if (inf.pl_flags & PL_FLAG_EXITED) {
        UpdateWaits();
        // DelegatePtraceEvent
        ptrace(PT_TO_SCE, pid2, (void *)1, 0);
        continue;
      }
      if (inf.pl_flags & (PL_FLAG_BORN | PL_FLAG_EXEC)) {
        ptrace(PT_TO_SCE, pid2, (void *)1, 0);
        continue;
      } else if (inf.pl_flags &
                 (PL_FLAG_FORKED | PL_FLAG_VFORKED | PL_FLAG_VFORK_DONE)) {
        // Inheret our hacks from LD_PRELOAD hack
        CProcInfo *parent = pinf;
        CProcInfo *child = GetProcInfByPid(inf.pl_child_pid);
        child->parent = pid2;
        child->hacks_array_ptr = parent->hacks_array_ptr;
        // Born again?
        parent->flags &= ~PIF_EXITED;
        ptrace(PT_TO_SCE, pid2, (void *)1, 0);
        continue;
      } else if (inf.pl_flags & PL_FLAG_CHILD) {
        struct ptrace_sc_remote rmt;
        int64_t args[1];
        args[0] = 0; // root
        rmt.pscr_args = args;
        rmt.pscr_nargs = 1;
        rmt.pscr_syscall = 183; // seteuid
        ptrace(PT_SC_REMOTE, pid2, (caddr_t)&rmt, sizeof(rmt));
        ptrace(PT_TO_SCX, pid2, (void *)1, 0);
        waitpid(pid2, NULL, 0);
        args[0] = 0; // wheel
        rmt.pscr_args = args;
        rmt.pscr_nargs = 1;
        rmt.pscr_syscall = 182; // setegid
        ptrace(PT_SC_REMOTE, pid2, (caddr_t)&rmt, sizeof(rmt));
        ptrace(PT_TO_SCX, pid2, (void *)1, 0);
        waitpid(pid2, NULL, 0);
        ptrace(PT_TO_SCE, pid2, (void *)1, 0);
        continue;
      } else if (inf.pl_flags & PL_FLAG_SCE) {
        switch (inf.pl_syscall_code) {
        case MR_CHROOT_NOSYS: {
          char chrooted[1024];
          // In preload_hack.c,I use an indrtiect syscall,so use argument 1
          // instead of 0
          pinf->hacks_array_ptr = (CMrChrootHackPtrs *)ABIGetArg(pid2, 1);

          char *write_chroot_to = (char *)ABIGetArg(pid2, 2);
          ReadPTraceString(chrooted, pid2, write_chroot_to);
          GetChrootedPath(chrooted, pid2, "/");
          PTraceWriteBytes(pid2, write_chroot_to, chrooted,
                           strlen(chrooted) + 1);
          ABISetSyscall(pid2,
                        36); // Sync Takes no arguments,repalce with valid
                             // syscall(to avoid a signal for invalid syscall)
          ptrace(PT_TO_SCX, pid2, (void *)1, 0);
          waitpid(pid2, NULL, 0);
        } break;
        case 0: // syscall
          break;
        case 1: // exit
          break;
        case 2: // fork
          break;
        case 3: // read
          break;
        case 4: // write
          break;
        case 5: // open
          InterceptOpen(pid2);
          break;
        case 6: // close
          break;
        case 7: // wait4
          InterceptWait(pid2, ABIGetArg(pid2, 0), 0);
          break;
        case 532: // wait6
          InterceptWait(pid2, ABIGetArg(pid2, 1), 0);
          break;
        case 9: // link
          InterceptLink(pid2);
          break;
        case 10: // unlink
          InterceptUnlink(pid2);
          break;
        case 12: { // chdir
          InterceptChdir(pid2);
        }
        case 13: // fdchdir
          break;
        case 20: // getpid
          break;
        case 21: // mount
          InterceptMount(pid2);
          break;
        case 22: // unmount
          InterceptUnmount(pid2);
          break;
        case 23: // setuid
          FakeSuccess(pid2);
          break;
        case 24: // getuid
          FakeUser(pid2);
          break;
        case 25: // geteuid
          FakeUser(pid2);
          break;
        case 26: // ptrace
          InterceptPtrace(pid2);
          break;
        case 33: // access
          InterceptAccess(pid2);
          break;
        case 34: { // chflags
          INTERCEPT_FILE1(pid, 0);
        } break;
        case 39: // getppid TODO
          break;
        case 41: // dup
          break;
        case 43: { // getegid
          FakeGroup(pid2);
        } break;
        case 47: { // getgid
          FakeGroup(pid2);
        } break;
        case 49: { // getlogin
          // TODO check for root spoofing
          char const *who = "root";
          // int64_t len = ABIGetArg(pid2, 1);
          char *to = (char *)ABIGetArg(pid2, 0);
          ptrace(PT_TO_SCX, pid2, (void *)1, 0);
          if (to)
            WritePTraceString(NULL, pid2, to, who);
        } break;
        case 54: // ioctl
          break;
        case 56: { // revoke
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 57: { // symlink
          INTERCEPT_FILE2(pid2, 0, 1);
        } break;
        case 58: // readlink
          InterceptReadlink(pid2);
          break;
        case 59: // execve
          InterceptExecve(pid2);
          break;
        case 61: // chroot TODO
          break;
        case 66:
          break;
        case 73: // munmap
          break;
        case 74: // mprotect
          break;
        case 81: // getpgrp TODO
          break;
        case 82: // setpgid TODO
          break;
        case 83: // setitimer
          break;
        case 85: // swapon
          // no way
          break;
        case 92: // fcntl
          break;
        case 93: // select
          break;
        // Fake the chown homies as we are "root"
        case 15:  // chmod
        case 16:  // chown
        case 123: // fchmod
        case 124: // fchown
          FakeSuccess(pid2);
          break;
        case 126: // setreuid
          FakeSuccess(pid2);
          break;
        case 127: // setregid
          FakeSuccess(pid2);
          break;
        case 128: { // rnemae
          INTERCEPT_FILE2(pid2, 0, 1);
        } break;
        case 132: { // mkdifof
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 136 ... 138: { // mkdir/rmdir/utimes
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 147: // setsid TODO?
          break;
        case 148: { // qoutactl
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 161 ... 162: { // lgetfh
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 165: // sysarch
          break;
        case 181: // getgid
          FakeGroup(pid2);
          break;
        case 182: // setegid
          FakeGroup(pid2);
          break;
        case 183: // seteuid
          FakeSuccess(pid2);
          break;
        case 191: { // pathconf
          INTERCEPT_FILE1(pid2, 0);
        } break;
        /*case 202: { // TODO sysctl
        } break;*/
        case 204: { // undelete
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 207: // getpgid TODO
          break;
        case 253: // issetugid TODO
          break;
        case 254: {                 // lchown
          INTERCEPT_FILE1(pid2, 0); // This exits the syscall for us
          ABISetReturn(pid2, 0, 0);
        } break;
        case 274: { // luchmod
          INTERCEPT_FILE1(pid2, 0);
          ABISetReturn(pid2, 0, 0); // The syscall has exited if here
        } break;
        case 276: { // lutimes
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 326: // getcwd
          Intercept__Getcwd(pid2);
          break;
        case 338: // jail TODO
          break;
        case 340: // sigprocmask
          break;
        //__acl_xxxx_file
        case 347:
        case 348:
        case 351:
        case 353: {
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 356 ... 358: { //	extattr_set_file	extattr_get_file
                            // extattr_delete_file
          INTERCEPT_FILE1(pid2, 0);
        }
        case 376: { // eaccess
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 378: // nmount
          InterceptNmount(pid2);
          break;
        case 387:
        case 389: { //__mac_get_file/__mac_set_file
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 391: { // lchflags
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 409:
        case 411: { // mac_get_link/set_link
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 412 ... 414: { // extattr_set_link/get_link/delete_link
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 416: // sigaction
          break;
        case 417: // sigreturn
          break;
        case 436: // jail_attach
          break;
        case 475: // pread
          break;
        case 476: // pwrite
          break;
        case 477: // mmap
          break;
        case 479: // shm_unlink
          InterceptAccessTruncate(pid2);
          break;
        case 483: // shm_unlink
          InterceptAccessShmUnlink(pid2);
          break;
          break;
        case 500: // readlinkat
          InterceptReadlinkAt(pid2);
          break;
        case 489 ... 499: // openat xxx_at
        case 503: {
          if (inf.pl_syscall_code == 492) {
          } else {
            INTERCEPT_FILE1_ONLY_ABS(pid2,
                                     1); // This exits the syscall for us
            // TODO check if "root"
            if (inf.pl_syscall_code == 490 || inf.pl_syscall_code == 491)
              ABISetReturn(pid2, 0, 0);
          }
        } break;
        case 501: { // renameat
          pid_t pid = pid2;
          char backupstr[1024], backupstr2[1024];
          char have_str[1024], chroot[1023], have_str2[1024], chroot2[1024];
          int64_t backup_len = -1, backup_len2 = -1;
          char *orig_ptr, *orig_ptr2, *dumb_to;
          orig_ptr = (void *)ABIGetArg(pid, 1);
          orig_ptr2 = (void *)ABIGetArg(pid, 3);
          ReadPTraceString(have_str, pid, orig_ptr);
          ReadPTraceString(have_str2, pid, orig_ptr2);
          dumb_to = orig_ptr2;
          if (have_str[0] == '/') {
            GetChrootedPath(chroot, pid, have_str);
            backup_len = WritePTraceString(backupstr, pid, orig_ptr, chroot);
            dumb_to = orig_ptr + backup_len + 1;
          } else {
            dumb_to = orig_ptr + strlen(have_str) + 1;
          }

          // orig_ptr[0]orig_ptr's string
          if (have_str2[0] == '/') {
            GetChrootedPath(chroot2, pid, have_str2);
            backup_len2 = WritePTraceString(backupstr2, pid, dumb_to, chroot2);
          } else
            backup_len2 =
                WritePTraceString(backupstr2, pid, dumb_to, have_str2);
          ABISetArg(pid, 3, (uint64_t)dumb_to);

          ptrace(PT_TO_SCX, pid, (void *)1, 0);
          waitpid(pid, NULL, 0);

          if (backup_len != -1)
            PTraceRestoreBytes(pid, orig_ptr, backupstr, backup_len);
          if (backup_len2 != -1)
            PTraceRestoreBytes(pid, dumb_to, backupstr2, backup_len2);
        } break;
        case 502: { // symlinkat
          pid_t pid = pid2;
          char backupstr[1024], backupstr2[1024];
          char have_str[1024], chroot[1023], have_str2[1024], chroot2[1024];
          int64_t backup_len = -1, backup_len2 = -1;
          char *orig_ptr, *orig_ptr2, *dumb_to;
          orig_ptr = (void *)ABIGetArg(pid, 0);
          orig_ptr2 = (void *)ABIGetArg(pid, 2);
          ReadPTraceString(have_str, pid, orig_ptr);
          ReadPTraceString(have_str2, pid, orig_ptr2);
          dumb_to = orig_ptr2;
          if (have_str[0] == '/') {
            GetChrootedPath(chroot, pid, have_str);
            backup_len = WritePTraceString(backupstr, pid, orig_ptr, chroot);
            dumb_to = orig_ptr + backup_len + 1;
          } else {
            dumb_to = orig_ptr + strlen(have_str) + 1;
          }
          // orig_ptr[0]orig_ptr's string
          if (have_str2[0] == '/') {
            GetChrootedPath(chroot2, pid, have_str2);
            backup_len2 = WritePTraceString(backupstr2, pid, dumb_to, chroot2);
          } else
            backup_len2 =
                WritePTraceString(backupstr2, pid, dumb_to, have_str2);
          ABISetArg(pid, 2, (uint64_t)dumb_to);

          ptrace(PT_TO_SCX, pid, (void *)1, 0);
          waitpid(pid, NULL, 0);

          if (backup_len != -1)
            PTraceRestoreBytes(pid, orig_ptr, backupstr, backup_len);
          if (backup_len2 != -1)
            PTraceRestoreBytes(pid, dumb_to, backupstr2, backup_len2);
        } break;
        case 506 ... 508: // jail shit. TODO
          break;
        case 551: // fstat
          InterceptFstat(pid2);
          break;
        case 552: // fstatat
          InterceptFstatat(pid2);
          break;
        case 553:
          InterceptFhstat(pid2);
          break;
        case 554: // getdirentries
          // Filename is from fd
          break;
        case 540: // chflagsat
          break;
        case 547: // utimensat "touch"
        {
          INTERCEPT_FILE1_ONLY_ABS(pid2, 1);
        } break;
          break;
        case 557: // getfsstat TODO
          break;
        case 559: { // mknodat
          INTERCEPT_FILE1_ONLY_ABS(pid2, 1);
        } break;
        case 563: // getrandom
          break;
        case 564: { // getfhat
          INTERCEPT_FILE1_ONLY_ABS(pid2, 1);
        } break;
        case 565: { // fhlink
          INTERCEPT_FILE1(pid2, 1);
        } break;
        case 566: { // fhlinkat
          INTERCEPT_FILE1_ONLY_ABS(pid2, 2);
        } break;
        case 568: { // funlinkat
          INTERCEPT_FILE1_ONLY_ABS(pid2, 1);
        } break;
        case 572: // shm_rename
          InterceptShmRename(pid2);
          break;
        case 573: // sigfastblock
          break;
        case 574: // realpathat
        {
          InterceptRealPathAt(pid2);
          break;
        }
        default:;
        }
        goto defacto;
      } else {
      defacto:
        if (pinf->flags & PIF_TO_SCX_ONLY) {
          pinf->flags &= ~PIF_TO_SCX_ONLY;
          ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
          continue;
        }
        if (!(pinf->flags & PIF_WAITING)) {
          if (WIFSTOPPED(cond)) {
            if (WSTOPSIG(cond) != SIGTRAP || pinf->debugged_by) {
              pid_t debugged_by = pinf->debugged_by;
              if (!debugged_by) {
                ptrace(PT_TO_SCE, pid2, (void *)1, WSTOPSIG(cond)); // !=SIGTAP
              } else if (debugged_by) {
                if (WSTOPSIG(cond) == SIGTRAP &&
                    !!(inf.pl_flags & (PL_FLAG_SCE | PL_FLAG_SCX))) {
                  goto ignore;
                }
                DelegatePtraceEvent(pinf->debugged_by, pid2, cond);
                kill(debugged_by, SIGCHLD);
              }
              UpdateWaits();
              continue;
            }
          }
        ignore:;
          ptrace(PT_TO_SCE, pid2, (void *)1, 0);
        }
      }
    }
  } else {
    const char *dummy_argv[argc - 3 + 1 + 1];
    int64_t r, has_ld_preload;
    dummy_argv[0] = argv[2];
    for (idx = 0; idx != argc - 3; idx++)
      dummy_argv[idx + 1] = argv[idx + 3];
    dummy_argv[argc - 3 + 1] = NULL;
    ptrace(PT_TRACE_ME, pid, NULL, 0);
    GetChrootedPath(chroot_bin, pid, argv[2]);
    int f, f2;
    // Add libpl_hack.so to the chroot to patch elf_aux_info
#define DLLNAME "libpl_hack.so"
    if (-1 == (f = open(DLLNAME, O_RDONLY))) {
      fprintf(stderr,
              "I need the " DLLNAME " file to patch elf_aux_info please.\n");
      return 1;
    }
    struct stat fst;
    fstat(f, &fst);
    char *chroot_root = realpath(argv[1], NULL);
    chdir(argv[1]);
    if (access(DLLNAME, F_OK)) {
      struct stat fst;
      fstat(f, &fst);
      f2 = open(DLLNAME, O_WRONLY | O_CREAT, 0755);
      ssize_t wrb;
      for (off_t o = 0; o < fst.st_size; o += wrb) {
        wrb = copy_file_range(f, NULL, f2, NULL, SSIZE_MAX, 0);
        if (-1 == wrb) {
          fprintf(stderr, "Failed copying library: %s\n", strerror(errno));
          return 1;
        }
      }
      close(f2);
    } else
      chmod(DLLNAME, 0755);
    close(f);
    char nenv_d[256][1024];
    char *nenv[256];
    has_ld_preload = 0;
    for (r = 0; env[r]; r++) {
      if (Startswith(env[r], "LD_PRELOAD=") && 0) {
        has_ld_preload = 1;
        snprintf(nenv_d[r], sizeof *nenv_d, "%s %s", env[r], "/" DLLNAME);
      } else
        strcpy(nenv_d[r], env[r]);
      nenv[r] = nenv_d[r];
    }
    if (!has_ld_preload) {
      sprintf(nenv_d[r], "LD_PRELOAD=/%s", DLLNAME);
      nenv[r] = nenv_d[r];
      r++;
    }
    nenv[r] = "LD_LIBRARY_PATH=/lib:/usr/lib:/usr/local/lib";
    r++;
    nenv[r] = NULL;
    execve(chroot_bin, dummy_argv, nenv);
  }
}
