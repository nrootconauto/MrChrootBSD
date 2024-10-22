
#include "abi.h"
#include "hash.h"
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
#define assert(f) if(!(f)) {fprintf(stderr,"Failure at " __FILE__  "(%d). Your on your own!!!\n",__LINE__); abort();}
// Fakes a succeffusl return
static void FakeSuccess(pid_t pid) {
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, 0, 0);
  ABISetReturn(pid, 0, 0);
}
#define ptrace ptrace2
CMountPoint mount_head, *root_mount;
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
  int ngrps;
  gid_t groups[NGROUPS_MAX+1];
  uid_t uid,suid,euid; //suid==saved gid,[g/s]etresuid 311/312
  gid_t gid,sgid,egid;
  char *login;
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
      free(cur->login);
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
  int64_t trim, best_len = 0, len, prefix;
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
  prefix = strlen(best->src_path);
  strcpy(cur, best->src_path);
  StrMove(cur + prefix, from + trim);
  memcpy(cur, best->src_path, prefix);
  if (to)
    strcpy(to, buf);
  return strlen(buf);
}
static struct procstat *ps;
static int64_t GetProcCwd(char *to, pid_t pid);
static int64_t FdToStr(char *to, pid_t pid, int fd) {
  unsigned cnt = 0;
  int64_t res_cnt = 0;
  char buf[1024];
  if (fd == AT_FDCWD) {
    return GetProcCwd(to, pid);
  }
  if (!ps)
    ps = procstat_open_sysctl();
  struct filestat_list *head;
  // See /usr/src/use.bin/procstat in FreeBSD
  struct filestat *fs;
  struct kinfo_proc *kprocs = procstat_getprocs(ps, KERN_PROC_PID, pid, &cnt);
  for (unsigned i = 0; i < cnt; i++) {
    head = procstat_getfiles(ps, kprocs, 0);
    STAILQ_FOREACH(fs, head, next) {
      if (fs->fs_fd == fd && fs->fs_path) {
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

static int64_t GetProcCwd(char *to, pid_t pid) {
  unsigned cnt = 0;
  int64_t res_cnt = 0;
  char buf[1024];
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
  *(cur = calloc(sizeof(*cur), 1)) = (CProcInfo){.next = &proc_head,
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
    /*printf("imp layer\n");*/
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

int64_t NormailizePath(char *to, const char *path) {
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
static int64_t GetChrootedPath0(char *to, pid_t pid, const char *path,
                                CMountPoint **have_mp) {
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
    if (max_match < (len = strlen(mp->src_path))) {
      if (Startswith(result, mp->src_path)) {
        max_match = len;
        choose = mp;
      }
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

  if (have_mp)
    *have_mp = choose;

  if (to)
    strcpy(to, s);
  return strlen(s);
}
static int64_t GetChrootedPath(char *to, pid_t pid, const char *path) {
  return GetChrootedPath0(to, pid, path, NULL);
}
char *DatabasePathForFile(char *to, pid_t pid, const char *path) {
  CMountPoint *mp = NULL;
  char dummy[1024];
  GetChrootedPath0(dummy, pid, path, &mp);
  if (!mp->document_perms)
	return NULL;
  sprintf(to, "%s/%s", mp->db_path, dummy + strlen(mp->dst_path));
  NormailizePath(to,to);
  return to;
};
static char *ChrootedRealpath(char *to, pid_t p, char *path) {
  char dst[1024];
  GetChrootedPath(dst, p, path);
  UnChrootPath(to, dst);
  return to;
}
static uint32_t FilePerms(char *fn) {
  CHashEntry dummy;
  if (HashTableGet(&dummy, fn)) {
    return dummy.perms;
  }
  return 0755; //??? TODO test if dir or file
}
static void ChrootDftOwnership(char *pa, pid_t p) {
  char dst[1024];
  CProcInfo *inf = GetProcInfByPid(p);
  ChrootedRealpath(dst, p, pa);
  HashTableSet(dst, inf->uid, inf->gid, FilePerms(dst));
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
  ABISetReturn(pid, 0, 0);
}
static void InterceptChown(pid_t pid) {
  CProcInfo *inf = GetProcInfByPid(pid);
  char have[1024], c[1024], failed;
  uid_t u = ABIGetArg(pid, 1);
  gid_t g = ABIGetArg(pid, 2);
  ReadPTraceString(have, pid, (char *)ABIGetArg(pid, 0));
  GetChrootedPath(c, pid, have);
  { INTERCEPT_FILE1(pid, 0); }
  // TODO PERM CHECK
  ABIGetReturn(pid, &failed);
  if (!failed) {
    UnChrootPath(have, c);
    HashTableSet(have, u, g, FilePerms(have));
  }
  ABISetReturn(pid, 0, 0);
}
#define PERM_WHAT_X 0b001
#define PERM_WHAT_W 0b010
#define PERM_WHAT_R 0b100

// Returns 0 if yat,else -errno
static int HasPerms(int af, pid_t p, char *path_) {
  char path[1024];
  NormailizePath(path, path_);
  int what = 0;
  if (af & W_OK)
    what |= PERM_WHAT_W;
  if (af & X_OK)
    what |= PERM_WHAT_X;
  if (af & R_OK)
    what |= PERM_WHAT_R;
  if (!ps)
    ps = procstat_open_sysctl();
  char dst[1024], uc[1024];
  uint32_t masked;
  struct filestat_list *head;
  // See /usr/src/use.bin/procstat in FreeBSD
  struct filestat *fs;
  CProcInfo *inf = GetProcInfByPid(p);
  int ngrps = inf->ngrps;
  gid_t *groups = inf->groups;
  int cnt = 0;
  CHashEntry *e, dummy;
  GetChrootedPath(dst, p, path);
  UnChrootPath(uc, dst);
  struct stat st;
  // Nroot here,access follows symbolic links,use stat and check for poo poo
  // sauce I dont want the value of the symbolic link,i want the link iteslef
  if ((af & (R_OK | X_OK)) && 0 != lstat(dst, &st)) {
    if (errno == ENOENT)
      return -ENOENT;
  }
  // Nroot here,if we W_OK is set,the file doesnt have to exist,only the
  // directory we are in needs to exist for a "new" file
  if ((af & W_OK) && 0 != lstat(dst, &st)) {
    if (errno == ENOENT) { // Check directory's perms
      char dir[1024], *ptr;
      size_t at = strlen(uc);
      strcpy(dir, uc);
      while (--at >= 0) {
        if (dir[at] == '/') {
          dir[at] = 0;
          break;
        }
      }
      if (dir[0] != 0)
        return HasPerms(F_OK | af, p, dir);
    }
  }
  if (e = HashTableGet(&dummy, uc)) {
	  //printf("%s,%o",uc,e->perms);
    // Try use
    if (e->uid == inf->uid) {
      masked = (e->perms >> 6) & 0b111;
      if (masked & what)
        return 0;
    }
    // Try groups
    while (--ngrps >= 0) {
      if (inf->groups[ngrps] == e->gid) {
        masked = (e->perms >> 3) & 0b111;
        if (masked & what)
          return 0;
      }
    }
    // Try other
    masked = e->perms & 0b111;
    if (masked & what)
      return 0;
    return -EACCES;
  }
  return 0; //???
}

static void InterceptAccess(pid_t pid) {
  int passed;
  char r, failed;
  char what[1024], have[1024];
  int want = ABIGetArg(pid, 1);
  ReadPTraceString(have, pid, (char *)ABIGetArg(pid, 0));
  GetChrootedPath(what, pid, have);
  { INTERCEPT_FILE1(pid, 0); }
  passed = ABIGetReturn(pid, &failed);
  // User running MrChrootBSD must have access to the file,then we apply
  // emulated perms
  UnChrootPath(what,what);
  if (!failed && 0 == HasPerms(R_OK,pid, what)) {
    ABISetReturn(pid, 0, 0);
  } else if (failed) {
    ABISetReturn(pid, passed, 1);
  } else {
    // Invalid permsision
    ABISetReturn(pid, -HasPerms(R_OK, pid, have), 0);
  }
}

static void InterceptOpen(pid_t pid) {
  CProcInfo *inf = GetProcInfByPid(pid);
  int64_t fd, flags = ABIGetArg(pid, 1);
  char failed;
  char *orig_ptr = (char *)ABIGetArg(pid, 0);
  char have_str[1024], chroot[1024];
  ReadPTraceString(have_str, pid, orig_ptr);
  { INTERCEPT_FILE1(pid, 0); }
  fd = ABIGetReturn(pid, &failed);
  if (!failed) {
    if (flags & O_CREAT)
      ChrootDftOwnership(have_str, pid);
  }
}
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
static uid_t FileUid(const char *path);
static gid_t FileGid(const char *path);
static void InterceptExecve(pid_t pid) {
  char have_str[1024], chroot[1024], backup[1024], poop_ant[1024];
  char *orig_ptr, **argv, **env;
  char *ptr, *ptr2, *command, *argument;
  int64_t fd, args[3], bulen, extra_args = 0, perms;
  struct ptrace_sc_remote rmt;
  CProcInfo *pinf = GetProcInfByPid(pid);
  orig_ptr = (void *)ABIGetArg(pid, 0);
  argv = (void *)ABIGetArg(pid, 1);
  env = (void *)ABIGetArg(pid, 2);
  ReadPTraceString(have_str, pid, orig_ptr);
  GetChrootedPath(chroot, pid, have_str);
  perms = FilePerms(have_str);
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
    int64_t i;
    char *av;
    for (i = 0; av = PTraceReadPtr(pid, argv + i); i++) {
      char ass[1023];
      PTraceRead(pid, ass, av, 1024);
    }
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
  if (perms & S_ISUID) {
    pinf->euid = FileUid(have_str);
  }
  if (perms & S_ISGID) {
    pinf->egid = FileGid(have_str);
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

static void InterceptLink(pid_t pid) {
  char name[1024];
  char failed;
  CProcInfo *inf = GetProcInfByPid(pid);
  int64_t r;
  ReadPTraceString(name, pid, (char *)ABIGetArg(pid, 0));
  { INTERCEPT_FILE2(pid, 0, 1); }
  r = ABIGetReturn(pid, &failed);
  if (!failed) {
    ChrootDftOwnership(name, pid);
  }
}

static void InterceptUnlink(pid_t pid) {
  INTERCEPT_FILE1(pid, 0); // TODO remove hash table }
}
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

static void InterceptChmod(pid_t pid) {
  CProcInfo *inf = GetProcInfByPid(pid);
  char have[1024], real[1024], failed;
  uint32_t perms = ABIGetArg(pid, 1);
  ReadPTraceString(have, pid, (char *)ABIGetArg(pid, 0));
  { INTERCEPT_FILE1(pid, 0); }
  ChrootedRealpath(real, pid, have);
  ABIGetReturn(pid, &failed);
  // TODO PERM CHECK
  if (!failed) {
    HashTableSet(real, FileUid(real), FileGid(real), perms);
  }
  ABISetReturn(pid, 0, 0);
}

static void InterceptSetuid(pid_t pid) {
  CProcInfo *inf = GetProcInfByPid(pid);
  uid_t want = ABIGetArg(pid, 0);
  // Sets only if inf->ruid==root||(inf->suid==want||inf->euid==want)
  if (inf->uid == 0) {
  pass:
    inf->suid = inf->euid = inf->uid = want;
  } else if (inf->suid == want || inf->euid == want) {
    goto pass;
  }
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, NULL, 0);
  ABISetReturn(pid, 0, 0);
}
static void InterceptSeteuid(pid_t pid) {
  CProcInfo *inf = GetProcInfByPid(pid);
  uid_t want = ABIGetArg(pid, 0);
  if (inf->uid == 0) {
  pass:
    inf->euid = want;
  } else if (inf->suid == want || inf->euid == want) {
    goto pass;
  }
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, NULL, 0);
  ABISetReturn(pid, 0, 0);
}
static void InterceptGetuid(pid_t pid) {
  CProcInfo *inf = GetProcInfByPid(pid);
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, NULL, 0);
  ABISetReturn(pid, inf->uid, 0);
}

static void InterceptGeteuid(pid_t pid) {
  CProcInfo *inf = GetProcInfByPid(pid);
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, NULL, 0);
  ABISetReturn(pid, inf->euid, 0);
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

static gid_t FileGid(const char *path) {
  CHashEntry *ent, dummy;
  struct stat st;
  char dst[1024];
  if (ent = HashTableGet(&dummy, path)) {
    return ent->gid;
  }
  return 0;
}

static uid_t FileUid(const char *path) {
  CHashEntry *ent, dummy;
  struct stat st;
  if (ent = HashTableGet(&dummy, path)) {
    return ent->uid;
  }
  return 0;
}
static char *AtSytle(char *, pid_t, int64_t, int64_t);
static void InterceptFstat(pid_t pid) {
  uid_t dummyu = 0;
  gid_t dummyg = 0;
  uint32_t perms=0755;
  struct stat st;
  uint8_t *ptr = (void *)ABIGetArg(pid, 1);
  char who[1024];
  FdToStr(who, pid, ABIGetArg(pid, 0));
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, NULL, 0);
  if (who) {
    dummyu = FileUid(who);
    dummyg = FileGid(who);
    perms=FilePerms(who);
  }
#define W(p, T, m, V)                                                          \
  PTraceWrite(pid, p + offsetof(T, m), &(size_t){V}, sizeof declval(T).m)
  W(ptr, struct stat, st_uid, dummyu);
  W(ptr, struct stat, st_gid, dummyg);
  //W(ptr, struct stat, st_mode, perms);
}
static void InterceptFstatat(pid_t pid) {
  void *ptr = (void *)ABIGetArg(pid, 2);
  char who[1024];
  AtSytle(who, pid, 0, 1);
  UnChrootPath(who, who);
  W(ptr, struct stat, st_uid, FileUid(who));
  W(ptr, struct stat, st_gid, FileGid(who));
  //W(ptr, struct stat, st_mode, FilePerms(who));
}

#undef W

static void FakeGroup(pid_t pid) {
  uid_t who = 0;
  CProcInfo *pinf = GetProcInfByPid(pid);
  if (pinf) {
    who = pinf->gid;
  }
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, 0, 0);
  ABISetReturn(pid, who, 0);
}

static CMountPoint *AddMountPoint(const char *dst, const char *src) {
  char *rp;
  CMountPoint *mp = malloc(sizeof *mp);
  strcpy(mp->src_path, src);
  strcpy(mp->dst_path, dst);
  rp = realpath(dst, NULL);
  if (rp) {
    strcpy(mp->dst_path, rp);
    free(rp);
  }
  mp->next = mount_head.next;
  mp->last = &mount_head;
  mp->next->last = mp;
  mp->last->next = mp;
  return mp;
}
static void FakeUser(pid_t pid) {
  uid_t who = 0;
  CProcInfo *pinf = GetProcInfByPid(pid);
  if (pinf) {
    who = pinf->gid;
  }
  ptrace(PT_TO_SCX, pid, (void *)1, 0);
  waitpid(pid, 0, 0);
  ABISetReturn(pid, who, 0);
}
static char *AtSytle(char *_to, pid_t pid, int64_t fd, int64_t path) {
  char dst[1024], chroot[1024], rel[1024], old[1024];
  char to[1024];
  char *ptr;
  int have_fd;
  int is_rel=0;
  ReadPTraceString(dst, pid, ptr = (char *)ABIGetArg(pid, path));
  if (dst[0] == '/') { // Abolsute
    GetChrootedPath(to, pid, dst);
  } else {
    strcpy(to, dst);
    is_rel=1;
    have_fd=ABIGetArg(pid,fd);
  }
  int64_t restore = WritePTraceString(old, pid, ptr, to);
  ptrace(PT_TO_SCX, pid, (caddr_t)1, 0);
  waitpid(pid, NULL, 0);
  PTraceRestoreBytes(pid, ptr, old, restore);
  if (_to&&is_rel) {
	FdToStr(rel,pid,have_fd);
    sprintf(chroot,"%s/%s",rel,to);
    GetChrootedPath(_to,pid,chroot);
  } else if(_to&&!is_rel) {
	 NormailizePath(_to,to);
  }
  return _to;
}

static void InterceptLinkat(pid_t pid) {
  char a[1024], b[1024];
  char old[2048];
  char total[2048];
  char *write_to = (char *)ABIGetArg(pid, 1);
  int64_t i;
  for (i = 0; i != 2; i++) {
    char dst[1024], rel[1024];
    char *to = i ? b : a;
    char *ptr;
    ReadPTraceString(dst, pid, ptr = (char *)ABIGetArg(pid, 1 + 2 * i));
    if (dst[0] == '/') { // Abolsute
      GetChrootedPath(to, pid, dst);
    } else
      strcpy(to, dst);
  }
  int64_t total_len = 2 + strlen(a) + strlen(b);
  sprintf(total, "%s%c%s", a, 0, b);
  PTraceRead(pid, old, write_to, total_len);
  PTraceWriteBytes(pid, write_to, total, total_len);
  ABISetArg(pid, 3, (int64_t)(write_to + 1 + strlen(a)));
  ptrace(PT_TO_SCX, pid, (caddr_t)1, 0);
  waitpid(pid, NULL, 0);
  PTraceRestoreBytes(pid, write_to, old, total_len);
}
int main(int argc, const char *argv[], const char **env) {
  signal(SIGHUP, SIG_IGN); //Whoops
  pid_t pid, pid2;
  int64_t idx;
  int ch;
  char chroot_bin[1024];
  char hflag = 0;
  char tflag = 0;
  if (argc < 3) {
  help:
    fprintf(stderr,
            "Usage %s [chroot] [shell] ...\n"
            "  %s -t [base.tar] [chroot]\n"
            "	-h	Display this help message\n"
            "	-t	Extract a tar with valid permisons into [chroot]\n",
            argc > 0 ? argv[0] : "mrchroot");
    return 1;
  }
  while ((ch = getopt(argc, argv, "th")) != -1) {
    if (ch == 'h') {
      hflag = 1;
    } else if (ch == 't') {
      tflag = 1;
    } else if (ch == '?') {
      hflag = 1; // getopt sets '?' on error
    }
  }
  argv += optind;
  argc -= optind;

  if (argv < 2 || hflag) {
    goto help;
  }

  proc_head.last = &proc_head;
  proc_head.next = &proc_head;

  mount_head.last = &mount_head;
  mount_head.next = &mount_head;

  wait_events.last = &wait_events;
  wait_events.next = &wait_events;

  char *prog = argv[1], *chroot = argv[0];
  char *tarball = argv[0];
#define TARROOT "/tarextract"
  if (tflag) {
    chroot = argv[1];
    root_mount = AddMountPoint("/", "/");
    CMountPoint *tarc = AddMountPoint(chroot, TARROOT);
    tarc->document_perms = 1;
    strcpy(tarc->db_path, "/");
  } else {
    root_mount = AddMountPoint(chroot, "/");
    root_mount->document_perms = 1;
    strcpy(root_mount->db_path, "/");
    AddMountPoint("/dev", "/dev");
    AddMountPoint("/proc", "/proc");
  }

  if ((pid = fork())) {
    HashTableInit("./perms.db");
    int cond;
    CProcInfo *pinf0 = GetProcInfByPid(pid);
    pinf0->uid = 0;
    pinf0->gid = 0;
    pinf0->euid = 0;
    pinf0->egid = 0;
    pinf0->ngrps = 1;
    pinf0->groups[0] = 0; // Wheel
    while ((pid2 = waitpid(-1, &cond,
                           WUNTRACED | WEXITED | WTRAPPED | WSTOPPED |
                               WCONTINUED))) {
      if (WIFEXITED(cond) && pid2 == pid) {
        HashTableDone();
        exit(0);
      }
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
        child->uid = parent->uid;
        child->gid = parent->gid;
        child->euid = parent->euid;
        child->egid = parent->egid;
        child->parent = pid2;
        child->hacks_array_ptr = parent->hacks_array_ptr;
        child->ngrps = parent->ngrps;
        if (parent->login) {
          child->login = strdup(parent->login);
        } else
          child->login = strdup("???");
        memcpy(child->groups, parent->groups, child->ngrps * sizeof(gid_t));
        // Born again?
        parent->flags &= ~PIF_EXITED;
        ptrace(PT_TO_SCE, pid2, (void *)1, 0);
        continue;
      } else if (inf.pl_flags & PL_FLAG_CHILD) {
        ptrace(PT_TO_SCE, pid2, (void *)1, 0);
        continue;
      } else if (inf.pl_flags & PL_FLAG_SCE) {
        // printf("%d\n",inf.pl_syscall_code);
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
        case 5: { // open
          int af = 0;
          int64_t want_ = ABIGetArg(pid2, 1);
          if (want_ & O_RDONLY)
            af |= R_OK;
          if (want_ & O_RDWR)
            af |= R_OK | W_OK;
          if (want_ & O_EXEC)
            af |= X_OK;
#define PERMCHECK(af, PATH)                                                    \
  {                                                                            \
    char dst[1024];                                                            \
    ReadPTraceString(dst, pid2, (char *)ABIGetArg(pid2, PATH));                \
    if (0 != HasPerms((af), pid2, dst)) {                                      \
      ABISetSyscall(pid2, 20); /*  Doesnt do anything*/                        \
      ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);                                  \
      waitpid(pid2, NULL, 0);                                                  \
      ABISetReturn(pid2, -HasPerms((af), pid2, dst), 1);                       \
      break;                                                                   \
    }                                                                          \
  }
          InterceptOpen(pid2);
        } break;
        case 6: // close
          break;
        case 7: // wait4
          InterceptWait(pid2, ABIGetArg(pid2, 0), 0);
          break;
        case 532: // wait6
          InterceptWait(pid2, ABIGetArg(pid2, 1), 0);
          break;
        case 9: // link
          PERMCHECK(W_OK, 1);
          InterceptLink(pid2);
          break;
        case 10: // unlink
          PERMCHECK(W_OK, 0);
          InterceptUnlink(pid2);
          break;
        case 12: { // chdir
          PERMCHECK(X_OK | F_OK, 0);
          InterceptChdir(pid2);
          break;
        }
        case 13: // fdchdir
#define FPERMCHECK(af, PATH)                                                   \
  {                                                                            \
    char dst[1024];                                                            \
    FdToStr(dst, pid2, ABIGetArg(pid2, 0));                                    \
    if (0 != HasPerms((af), pid2, dst)) {                                      \
      ABISetSyscall(pid2, 20); /*  Doesnt do anything*/                        \
      ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);                                  \
      waitpid(pid2, NULL, 0);                                                  \
      ABISetReturn(pid2, -HasPerms((af), pid2, dst), 1);                       \
      break;                                                                   \
    }                                                                          \
  }
          FPERMCHECK(X_OK | F_OK, 0);
          FakeSuccess(pid2);
          break;
        case 20: // getpid
          break;
        case 21: // mount
          InterceptMount(pid2);
          break;
        case 22: // unmount
          InterceptUnmount(pid2);
          break;
        case 26: // ptrace
          InterceptPtrace(pid2);
          break;
        case 33: // access
          PERMCHECK(R_OK, 0);
          InterceptAccess(pid2);
          break;
        case 34: { // chflags
          /*
           * 21 Nrootconauto ,ill have to emulate
           * SF_APPEND,SF_NOUNLINK,SF_IMMUATABLE
           * */
          PERMCHECK(W_OK | F_OK, 0);
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 35: { // fchflags
          /*
           * Look at 34:
           * */
          FPERMCHECK(W_OK | F_OK, 0);
          ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
          waitpid(pid2, NULL, 0);
        } break;
          break;
        case 37: { // kill
          /* 21 Nrootcomauto here,Ask nrootconauto to implement(and) killing
           *other procs (TODO handle p<=0)
           **/
          CProcInfo *me = GetProcInfByPid(pid2);
          pid_t want = ABIGetArg(pid2, 0);
          int poo = ABIGetArg(pid2, 1);
          if (want > 0) {
            CProcInfo *cur;
            ABISetSyscall(pid2, 20); // Dont do anyhthjing(getpid)
            for (cur = proc_head.next; cur != &proc_head; cur = cur->next) {
              if (want == cur->pid) {
                /*21 Nrootconauto
                 *  Must be
                 *   1. root
                 *   2. Same UID/EUID
                 *   3.(SIGCONT) session_ID(getpgid?)==session_ID(getpgid?) of
                 *other Ask Nroot for
                 * 	 1. sysctl.bsdconservative_signals
                 *
                 **/
                if ((me->uid == 0 || me->euid == 0) || // Super user
                    (cur->uid == me -> uid ||
                     cur->euid == me->uid) || // cur->real
                    (cur->uid == me -> euid ||
                     cur->euid == me->euid) || // cur->euid
                    (poo == SIGCONT && (getsid(want) == getsid(pid2)))) {
                  ptrace(PT_TO_SCX, pid2,(caddr_t) 1, 0);
                  waitpid(pid2, NULL, 0);
                  int e = kill(want, poo);
                  if (e)
                    ABISetReturn(pid2, e, 1);
                  else {
                    ABISetReturn(pid2, 0, 0);
                  }
                  break;
                } else {
                  // Not permiteed 2 kill
                  ptrace(PT_TO_SCX, pid2,(caddr_t) 1, 0);
                  waitpid(pid2, NULL, 0);
                  ABISetReturn(pid2, EPERM, 1);
                }
              }
            }
            ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
            waitpid(pid2, NULL, 0);
            ABISetReturn(pid2, ESRCH, 1);
          }
        } break;
        case 39: // getppid TODO
          break;
        case 41: { // dup
          CProcInfo *inf = GetProcInfByPid(pid2);
          CHashEntry *ent;
          ptrace(PT_TO_SCX, pid2, (void *)1, 0);
        } break;
        case 43: { // getegid
          // TODO wut is an egid
          CProcInfo *inf = GetProcInfByPid(pid2);
          ptrace(PT_TO_SCX, pid2, (void *)1, 0);
          waitpid(pid2, NULL, 0);
          ABISetReturn(pid2, inf->gid, 0);
        } break;
        case 47: { // getgid
          // TODO wut is an egid
          CProcInfo *inf = GetProcInfByPid(pid2);
          ptrace(PT_TO_SCX, pid2, (void *)1, 0);
          waitpid(pid2, NULL, 0);
          ABISetReturn(pid2, inf->gid, 0);
        } break;
        case 49: { // getlogin
          CProcInfo *pinf = GetProcInfByPid(pid2);
          // int64_t len = ABIGetArg(pid2, 1);
          char *to = (char *)ABIGetArg(pid2, 0);
          size_t len = ABIGetArg(pid2, 1);
          ptrace(PT_TO_SCX, pid2, (void *)1, 0);
          waitpid(pid2, NULL, 0);
          const char *name = "???";
          if (pinf->login) {
            name = pinf->login;
          }
          if (to && len >= 1 + strlen(name)) {
            WritePTraceString(NULL, pid2, to, name);
            ABISetReturn(pid2, 0, 0);
          } else {
            ABISetReturn(pid2, ERANGE, 1);
          }
        } break;
        case 50: // setlogin
        {
          char ln[MAXLOGNAME];
          ReadPTraceString(ln, pid2, (char *)ABIGetArg(pid2, 0));
          ABISetReturn(pid2, 0, 0); // TODO perms
        }
        case 54: // ioctl
          break;
        case 56: { // revoke
          PERMCHECK(W_OK | F_OK, 0);
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 57: { // symlink
          PERMCHECK(W_OK, 0);
          CProcInfo *inf = GetProcInfByPid(pid2);
          char name[1024];
          ReadPTraceString(name, pid2, (char *)ABIGetArg(pid2, 0));
          { INTERCEPT_FILE1(pid2, 1); }
          char failed;
          ABIGetReturn(pid2, &failed);
          if (!failed) {
            ChrootDftOwnership(name, pid2);
          }
        } break;
        case 58: // readlink
          InterceptReadlink(pid2);
          break;
        case 59: { // execve
          PERMCHECK(X_OK | F_OK, 0);
          InterceptExecve(pid2);
        } break;
        case 61: // chroot TODO
          break;
        case 66:
          break;
        case 73: // munmap
          break;
        case 74: // mprotect
          break;
        case 79: // getgroups
        {
          CProcInfo *pinf = GetProcInfByPid(pid2);
          long cnt = ABIGetArg(pid2, 0);
          if (cnt < pinf->ngrps) {
            if (cnt > 0)
              PTraceWrite(pid2, (void *)ABIGetArg(pid2, 1), pinf->groups,
                          cnt * sizeof(gid_t));
            ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
            waitpid(pid2, NULL, 0);
            ABISetReturn(pid2, EINVAL, 1);
          } else {
            PTraceWrite(pid2, (void *)ABIGetArg(pid2, 1), pinf->groups,
                        pinf->ngrps * sizeof(gid_t));
            ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
            waitpid(pid2, NULL, 0);
            ABISetReturn(pid2, pinf->ngrps, 0);
          }
        } break;
        case 80: { // setgroups
          CProcInfo *pinf = GetProcInfByPid(pid2);
          if (pinf->uid == 0 || pinf->euid == 0) {
            long cnt = ABIGetArg(pid2, 0);
            pinf->ngrps = cnt;
            PTraceRead(pid2, pinf->groups, (void *)ABIGetArg(pid2, 1),
                       cnt * sizeof(gid_t));
            ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
            waitpid(pid2, NULL, 0);
            ABISetReturn(pid2, 0, 0);
          } else {
            ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
            waitpid(pid2, NULL, 0);
            // Failure
          }
        } break;
        case 81: // getpgrp TODO
                 // Ask a kevalin
          break;
        case 82: // setpgid TODO
                 // You'll need to do some digging
          break;
        case 83: // setitimer
          break;
        case 85: // swapon
          // no way
          break;
        case 90:
          goto defacto;
        case 92: // fcntl
                 // NOT NOW
          break;
        case 93: // select
          break;
        case 15: // chmod
          PERMCHECK(W_OK, 0);
          InterceptChmod(pid2);
          break;
        case 16: // chown
          PERMCHECK(W_OK, 0);
          InterceptChown(pid2);
          break;
        case 23: // setuid 21
          InterceptSetuid(pid2);
          break;
        case 24: // getuid
          InterceptGetuid(pid2);
          break;
        case 25: // geteuid
          InterceptGeteuid(pid2);
          break;
        case 124: { // fchmod
          FPERMCHECK(F_OK | W_OK, 0);
          FakeSuccess(pid2);
          break;
        }
        case 122: { // settimeofday
          /*
           * Ask nroot,he will add it. I dont think anyone will notice for now
           */
          break;
        }
        case 123: { // fchown
          FPERMCHECK(F_OK | W_OK, 0);
          char who[1024];
          CProcInfo *pinf = GetProcInfByPid(pid2);
          ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
          waitpid(pid2, NULL, 0);
          if (FdToStr(who, pid2, ABIGetArg(pid2, 0))) {
            HashTableSet(who, ABIGetArg(pid2, 1), ABIGetArg(pid2, 2),
                         FilePerms(who));
          }
          ABISetReturn(pid2, 0, 0); // TODO success?
          break;
        }
        case 127: { // setregid
                    /*
                     * 21 Nroot here,im just copy-paste-swaping code from 126(segreuid)
                     * Normal users may only swp ugid<->egid
                     */
          CProcInfo *inf = GetProcInfByPid(pid2);
          gid_t wantu = ABIGetArg(pid2, 0);
          gid_t wante = ABIGetArg(pid2, 1);

          if ((inf->gid == 0 || inf->egid == 0) ||         // Superuser 21
              (inf->gid == wante && inf->egid == wantu)// swap gid<->egid
          ) {
            inf->gid = wantu;
            inf->egid = wante;
            FakeSuccess(pid2);
          } else if (wante == -1 || wantu == -1) {
            if (wante == inf->gid) {
              inf->egid = wante;
            }
            if (wantu == inf->egid) {
              inf->gid = wantu;
            }
            FakeSuccess(pid2);
          } else {
            ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
            waitpid(pid2, NULL, 0);
            ABISetReturn(pid2, EPERM, 1);
          }
          break;
        }

        case 126: { // setreuid
                    /*
                     * 21 Nroot.
                     * Normal users may only swp uid<->euid
                     */
          CProcInfo *inf = GetProcInfByPid(pid2);
          uid_t wantu = ABIGetArg(pid2, 0);
          uid_t wante = ABIGetArg(pid2, 1);

          if ((inf->uid == 0 || inf->euid == 0) ||         // Superuser 21
              (inf->uid == wante && inf->euid == wantu)// swap uid<->euid
          ) {
            inf->uid = wantu;
            inf->euid = wante;
            FakeSuccess(pid2);
          } else if (wante == -1 || wantu == -1) {
            if (wante == inf->uid) {
              inf->euid = wante;
            }
            if (wantu == inf->euid) {
              inf->uid = wantu;
            }
            FakeSuccess(pid2);
          } else {
            ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
            waitpid(pid2, NULL, 0);
            ABISetReturn(pid2, EPERM, 1);
          }
          break;
        }
        case 128: { // rename
                    /*
                     * 21 Nroot here,
                     *   Renaning a file only changes the ptr on disk,it does not
                     *"write/delete" the file           We only need R_OK 21
                     **/
          PERMCHECK(F_OK | R_OK, 0);
          PERMCHECK(W_OK, 1);
          char dst[1024], chr[1024], failed, chr2[1024];
          CProcInfo *inf = GetProcInfByPid(pid2);
          CHashEntry dummy, *ent = &dummy;
          ReadPTraceString(dst, pid2, (char *)ABIGetArg(pid2, 1));
          ReadPTraceString(chr, pid2, (char *)ABIGetArg(pid2, 0));
          ChrootedRealpath(chr, pid2, chr);
          uid_t u = FileUid(chr);
          gid_t g = FileGid(chr);
          uint32_t p = FilePerms(chr);
          INTERCEPT_FILE2(pid2, 0, 1);
          ABIGetReturn(pid2, &failed);
          ChrootedRealpath(chr2, pid2, dst);
          if (!failed) {
            /* 21 Nroot here,renamin' keeps perms ok
             */
            HashTableRemove(chr);
            HashTableSet(chr2, u, g, p);
          }
        } break;
        case 131: // flock
        {
          break;
        }
        case 132: { // mkfifo
          char dst[1024], failed;
          PERMCHECK(W_OK, 0);
          CProcInfo *inf = GetProcInfByPid(pid2);
          ReadPTraceString(dst, pid2, (char *)ABIGetArg(pid2, 0));
          INTERCEPT_FILE1(pid2, 0);
          ABIGetReturn(pid2, &failed);
          if (!failed)
            ChrootDftOwnership(dst, pid2);
        } break;
        case 136: { // mkdir
          char dst[1024], fail;
          PERMCHECK(W_OK, 0);
          CProcInfo *inf = GetProcInfByPid(pid2);
          ReadPTraceString(dst, pid2, (char *)ABIGetArg(pid2, 0));
          { INTERCEPT_FILE1(pid2, 0); }
          ABIGetReturn(pid2, &fail);
          if (!fail) {
            ChrootDftOwnership(dst, pid2);
          }
        } break;
        case 137: { // rmdir
          PERMCHECK(W_OK | F_OK, 0);
          INTERCEPT_FILE1(pid2, 0);
          break;
        }
        case 138: { // utimes
          PERMCHECK(W_OK | F_OK, 0);
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 147: // setsid TODO?
          break;
        case 148: { // qoutactl
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 161 ... 162: { // lgetfh
                            /* 21 Nrootconauto here,
                             *   What permisions does it need?
                             */
          INTERCEPT_FILE1(pid2, 0);
        } break;
        case 165: // sysarch
          break;
        case 181: { // setgid
        setgid:;
          /* 21 Nroot here
           * Basically we need be (of effectively) be root or have SSSame
           *gid/egid
           **/
          CProcInfo *inf = GetProcInfByPid(pid2);
          uid_t want = ABIGetArg(pid2, 0);
          if ((!inf->euid || !inf->uid) ||               // Super user
              (inf->gid == want || inf->egid == want)) { // uid or euid 21
            inf->sgid = inf->egid = inf->gid = want;
            ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
            waitpid(pid2, NULL, 0);
            ABISetReturn(pid2, 0, 0);
          } else {
            ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
            waitpid(pid2, NULL, 0);
            ABISetReturn(pid2, EPERM, 1);
          }
        } break;
        case 182: // setegid
        {
          CProcInfo *inf = GetProcInfByPid(pid2);
          uid_t want = ABIGetArg(pid2, 0);
          if((!inf->euid||!inf->uid)|| //Super user
			(inf->gid==want||inf->egid==want)) { //uid or euid 21
          inf->egid = want;
          ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
          waitpid(pid2, NULL, 0);
          ABISetReturn(pid2, 0, 0);
        }
          else {
            ABISetReturn(pid2, EPERM, 1);
          }
        }
        break;
      case 183: // seteuid
      {
        CProcInfo *inf = GetProcInfByPid(pid2);
        uid_t want = ABIGetArg(pid2, 0);
        if((!inf->euid||!inf->uid)|| //Super user
			(inf->uid==want||inf->euid==want)) {//uid or euid 21
          inf->euid = want;
          ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
          waitpid(pid2, NULL, 0);
          ABISetReturn(pid2, 0, 0);
    } else {
          ABISetReturn(pid2, EPERM, 1);
          }
      } break;
      case 191: { // pathconf
        PERMCHECK(F_OK | R_OK, 0);
        INTERCEPT_FILE1(pid2, 0);
      } break;
      case 192: { // lpathconf
        PERMCHECK(F_OK | R_OK, 0);
        INTERCEPT_FILE1(pid2, 0);
      } break;
      case 198: { // 64bit syscall
        break;
      }
      case 202: { // sysctl
        /* 21 Nroot here,ask him to add sysctls
         *  Keep in mind this is basically a poor man's hypervisor which runs
         * in userspace
         *
         */
        break;
      }
      case 204: { // undelete
        INTERCEPT_FILE1(pid2, 0);
      } break;
      case 206: {
        FPERMCHECK(W_OK, 0);
        AtSytle(NULL, pid2, 0,1);
        break;
      }
      case 207: // getpgid
        break;
      case 253: // issetugid
                /* 21 Nrootconauto
                 * Im  not taitned,lets just leave it at that
                 */
        FakeSuccess(pid2);
        break;
      case 254: { // lchown
        PERMCHECK(W_OK, 0);
        InterceptChown(pid2);
      } break;
      case 274: { // luchmod
        PERMCHECK(W_OK | F_OK, 0);
        InterceptChmod(pid2);
      } break;
      case 276: { // lutimes
        PERMCHECK(W_OK | F_OK, 0);
        INTERCEPT_FILE1(pid2, 0);
      } break;
      case 326: // getcwd
        Intercept__Getcwd(pid2);
        break;
      case 338: // jail
        /* 21 Nroot
         *   Stay tuned.
         */
        break;
      case 340: // sigprocmask
        break;
      case 311: { // setresuid
        uid_t u = ABIGetArg(pid2, 0);
        uid_t e = ABIGetArg(pid2, 1);
        uid_t s = ABIGetArg(pid2, 2);
        CProcInfo *pinf = GetProcInfByPid(pid2);
        pinf->suid = s;
        pinf->euid = e;
        pinf->uid = u;
        // TODO perms
        FakeSuccess(pid2);
        break;
      }
      case 312: { // setresgid
        CProcInfo *pinf = GetProcInfByPid(pid2);
        if (pinf->uid == 0 || pinf->uid == 0) {
          uid_t u = ABIGetArg(pid2, 0);
          uid_t e = ABIGetArg(pid2, 1);
          uid_t s = ABIGetArg(pid2, 2);
          if (s != -1)
            pinf->sgid = s;
          if (u != -1)
            pinf->gid = u;
          if (e != -1)
            pinf->egid = e;
          FakeSuccess(pid2);
        } else {
          ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
          waitpid(pid2, NULL, 0);
          ABISetReturn(pid2,EPERM, 1);
        }
        break;
      }
      case 360: { // getresuid
        CProcInfo *pinf = GetProcInfByPid(pid2);
        uid_t *up = (uid_t *)ABIGetArg(pid2, 0);
        uid_t *ep = (uid_t *)ABIGetArg(pid2, 1);
        uid_t *sp = (uid_t *)ABIGetArg(pid2, 2);
        PTraceWrite(pid2, up, &pinf->uid, sizeof(uid_t));
        PTraceWrite(pid2, ep, &pinf->euid, sizeof(uid_t));
        PTraceWrite(pid2, sp, &pinf->suid, sizeof(uid_t));
        FakeSuccess(pid2);
        break;
      }
      case 361: { // getresgid
        CProcInfo *pinf = GetProcInfByPid(pid2);
        gid_t *up = (gid_t *)ABIGetArg(pid2, 0);
        gid_t *ep = (gid_t *)ABIGetArg(pid2, 1);
        gid_t *sp = (gid_t *)ABIGetArg(pid2, 2);
        PTraceWrite(pid2, up, &pinf->gid, sizeof(gid_t));
        PTraceWrite(pid2, ep, &pinf->egid, sizeof(gid_t));
        PTraceWrite(pid2, sp, &pinf->sgid, sizeof(gid_t));
        FakeSuccess(pid2);
        break;
      }
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
        PERMCHECK(R_OK, 0);
        InterceptAccess(pid2);
      } break;
      case 378: // nmount
        InterceptNmount(pid2);
        break;
      case 387:
      case 389: { //__mac_get_file/__mac_set_file
        INTERCEPT_FILE1(pid2, 0);
      } break;
      case 391: { // lchflags
        PERMCHECK(W_OK | F_OK, 0);
        INTERCEPT_FILE1(pid2, 0);
      } break;
      case 409:
      case 411: { // mac_get_link/set_link
        INTERCEPT_FILE1(pid2, 0);
      } break;
      case 425 : //__acl_get_lni
			 PERMCHECK(R_OK,0);
        {INTERCEPT_FILE1(pid2, 0);}
			break;
			case 426 : //__acl_set_link
			 PERMCHECK(W_OK,0);
			 {INTERCEPT_FILE1(pid2, 0);}
			break;
			case 427 : //__acl_delte_link
			 PERMCHECK(W_OK,0);
			 {INTERCEPT_FILE1(pid2, 0);}
			break;
      case 438:
      case 439:
      case 450:;
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
      case 479: // truncate
        PERMCHECK(W_OK | F_OK, 0);
        InterceptAccessTruncate(pid2);
        break;
      case 480: // ltruncate
        PERMCHECK(W_OK | F_OK, 0);
        InterceptAccessTruncate(pid2);
        break;

      case 483: // shm_unlink
        PERMCHECK(W_OK | F_OK, 0);
        InterceptAccessShmUnlink(pid2);
        break;
      case 489: { // faccessat
#define FATPERMCHECK(write_to, af, FD, PATH)                                   \
  {                                                                            \
    char dst[1024], full[1024];                                                \
    ReadPTraceString(dst, pid2, (char *)ABIGetArg(pid2, PATH));                \
    if (dst[0] == '/')                                                         \
      strcpy(full, dst);                                                       \
    else {                                                                     \
      FdToStr(full, pid2, ABIGetArg(pid2, FD));                                \
      strcat(full, "/");                                                       \
      strcat(full, dst);                                                       \
    }                                                                          \
    if (write_to)                                                              \
      strcpy((write_to), full);                                                \
    if (0 != HasPerms((af), pid2, full)) {                                     \
      ABISetSyscall(pid2, 20); /*  Doesnt do anything*/                        \
      ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);                                  \
      waitpid(pid2, NULL, 0);                                                  \
      ABISetReturn(pid2, -HasPerms((af), pid2, dst), 1);                       \
      break;                                                                   \
    }                                                                          \
  }
        FATPERMCHECK(NULL, W_OK | F_OK, 0, 1);
        char dst[1024];
        AtSytle(dst, pid2, 0, 1);
        break;
      }

      case 490: // fchmodat
      {
        char use[1024];
        FATPERMCHECK(use, W_OK | F_OK, 0, 1);
        UnChrootPath(use, use);
        HashTableSet(use, FileUid(use), FileGid(use), ABIGetArg(pid2, 2));
        AtSytle(NULL, pid2, 0, 1);
        ABISetReturn(pid2, 0, 0);
        break;
      }
      case 491: { // fchownat
        char use[1024], failed;
        FATPERMCHECK(use, W_OK | F_OK, 0, 1);
        CProcInfo *inf = GetProcInfByPid(pid2);
        AtSytle(use, pid2, 0, 1);
        ABIGetReturn(pid2, &failed);
        if (!failed) {
          UnChrootPath(use, use);
          HashTableSet(use, ABIGetArg(pid2, 2), ABIGetArg(pid2, 3),
                       FilePerms(use));
        }
        ABISetReturn(pid2, 0, 0);
        break;
      }
      case 492: // fexecve 21
        /* 21 Nrootconauto
         *  Ask him to do this
         */
        AtSytle(NULL, pid2, 0, 1);
        break;
      case 494: // futimesat
        FATPERMCHECK(NULL, W_OK | F_OK, 0, 1);
        AtSytle(NULL, pid2, 0, 1);
        break;
      case 495: // linkat
        FATPERMCHECK(NULL, R_OK | F_OK, 0, 1);
        FATPERMCHECK(NULL, W_OK, 2, 3);
        InterceptLinkat(pid2);
        break;
      case 496: { // mkdirat
        char dst[1024];
        FATPERMCHECK(NULL, W_OK, 0, 1);
        AtSytle(dst, pid2, 0, 1);
        CProcInfo *inf = GetProcInfByPid(pid2);
        UnChrootPath(dst, dst);
        HashTableSet(dst, inf->uid, inf->gid, 0755);
      } break;
      case 497: { // mkfifoat
        FATPERMCHECK(NULL, W_OK, 0, 1);
        char dst[1024];
        AtSytle(dst, pid2, 0, 1);
        CProcInfo *inf = GetProcInfByPid(pid2);
        UnChrootPath(dst, dst);
        HashTableSet(dst, inf->uid, inf->gid, 0644);
      } break;
      case 499: { // openat	
        char dst[1024], failed;
        AtSytle(dst, pid2, 0, 1);
        CProcInfo *inf = GetProcInfByPid(pid2);
        int64_t fd = ABIGetReturn(pid2, &failed);
        if (!failed) {
          if (ABIGetArg(pid2, 2) & O_CREAT) {
            HashTableSet(dst, inf->uid, inf->gid, 0755);
          }
        }
      } break;
      case 500: { // readllnkat
        FATPERMCHECK(NULL, R_OK | F_OK, 0, 1);
        char dst[1024];
        char *b = (char *)ABIGetArg(pid2, 2);
        int64_t l = ABIGetArg(pid2, 3);
        AtSytle(dst, pid2, 0, 1);
      } break;
      case 501: { // renameat
        char tweenty[1024];
        char one[1024], failed;
        FATPERMCHECK(tweenty, W_OK, 2, 3);
        FATPERMCHECK(one, R_OK, 0, 1);
        UnChrootPath(one, one);
        UnChrootPath(tweenty, tweenty);
        uid_t u = FileUid(one);
        gid_t g = FileGid(one);
        uint32_t p = FilePerms(one);
        InterceptLinkat(pid2); // CLose enough
        ABIGetReturn(pid2, &failed);
        if (!failed) {
          /* 21 Nroot here,renamin' keeps perms ok
           */
          HashTableRemove(one);
          HashTableSet(tweenty, u, g, p);
        }
      } break;
      case 502: { // symlinkat
        char dst[1024];
        FATPERMCHECK(NULL, W_OK, 0, 1);
        AtSytle(dst, pid2, 1, 2);
        break;
      }
      case 503: // unlnikat
      {
        char del[1024];
        FATPERMCHECK(NULL, W_OK | F_OK, 0, 1);
        AtSytle(del, pid2, 0, 1);
        UnChrootPath(del, del);
        HashTableRemove(del);
      } break;
      case 506 ... 508: // jail stuff TODO
        break;
      case 513: // lpathcnf
        FPERMCHECK(R_OK, NULL)
        INTERCEPT_FILE1(pid2, 0);
        break;
      case 523: // getloginclass
        // TODO
        FakeSuccess(pid2);
        break;
      case 524: // setloginclass
        FakeSuccess(pid2);
        break;
      case 546: // futimes
        FPERMCHECK(W_OK, 0);
        ptrace(PT_TO_SCX, pid2, (caddr_t)1, 0);
        waitpid(pid2, NULL, 0);
        ABISetReturn(pid2, 0, 0);
        break;
      case 547: // utimenat
        FATPERMCHECK(NULL, W_OK | F_OK, 0, 1);
        AtSytle(NULL, pid2, 0, 1);
        break;
      case 551: // fstat
                // FPERMCHECK(R_OK|F_OK,0);
        InterceptFstat(pid2);
        break;
      case 552: { // fstatat
                  // FATPERMCHECK(NULL,R_OK|F_OK,0,1);
        InterceptFstatat(pid2);
      } break;
      case 553:
        break;
      case 554: // getdirentries
        // Filename is from fd
        break;
      case 540: // chflagsat
        FATPERMCHECK(NULL, W_OK | F_OK, 0, 1);
        AtSytle(NULL, pid2, 0, 1);
        break;
        break;
      case 556: // fstatfs
        break;
      case 559: { // mknodat
                  // Only super uses can make nodes
                  // AtSytle(NULL, pid2, 0, 1);
      } break;
      case 563: // getrandom
        break;

      case 564: { // getfhat
        FATPERMCHECK(NULL, R_OK | F_OK, 0, 1);
        AtSytle(NULL, pid2, 0, 1);
      } break;
      case 565: { // fhlink
        FPERMCHECK(W_OK, 1);
        INTERCEPT_FILE1(pid2, 1);
      } break;
      case 566: { // fhlinkat
        FATPERMCHECK(NULL, W_OK, 1, 2);
        AtSytle(NULL, pid, 1, 2);
      } break;
      case 568: { // funlinkat
        FATPERMCHECK(NULL, W_OK | F_OK, 1, 2);
        AtSytle(NULL, pid, 1, 2);
      } break;
      case 572: // shm_rename
        InterceptShmRename(pid2);
        break;
      case 573: // sigfastblock
        break;
      case 574: // realpathat
      {
        FATPERMCHECK(NULL, R_OK | F_OK, 0, 1);
        InterceptRealPathAt(pid2);
        break;
      }
      default:;
      }
      goto defacto;
    }
    else {
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
              ptrace(PT_TO_SCE, pid2, (void *)1,
                     WSTOPSIG(cond)); // !=SIGTAP
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
}
else if (!tflag) {
  const char *dummy_argv[argc - 2 + 1 + 1];
  int64_t r, has_ld_preload;
  dummy_argv[0] = prog;
  for (idx = 0; idx != argc - 2; idx++)
    dummy_argv[idx + 1] = argv[idx + 2];
  dummy_argv[argc - 2 + 1] = NULL;
  ptrace(PT_TRACE_ME, pid, NULL, 0);
  GetChrootedPath(chroot_bin, pid, prog);
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
  char *chroot_root = realpath(chroot, NULL);
  chdir(chroot);
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
else if (tflag) {
  if (access(chroot, W_OK | X_OK)) { // dirs need X to be useable
    fprintf(stderr, "Cant access '%s'\n", chroot);
    exit(1);
  }
  if (access(tarball, R_OK)) {
    fprintf(stderr, "Cant access '%s'\n", tarball);
    exit(1);
  }
  char *t = realpath(tarball, NULL);
  const char *args[7];
  args[0] = "tar";
  args[1] = "--same-owner";
  args[2] = "-C";
  args[3] = TARROOT;
  args[4] = "-xvf";
  args[5] = t;
  args[6] = NULL;
  ptrace(PT_TRACE_ME, pid, NULL, 0);
  execvp("tar", args);
}
}
