#include "abi.h"
#include "fd_cache.h"
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
#include <sys/procctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
/* clang-format off */
#include <kvm.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libprocstat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <libutil.h>
#include <pthread.h>
#include <sys/procctl.h>
#define class(x)                                                               \
  typedef struct x x;                                                          \
  struct x

static struct __wrusage mc_current_usage;
static siginfo_t mc_current_siginfo;
CMountPoint mount_head, *root_mount;
CChrootRoot chroot_root;
class (CTidWait) {
	CTidWait *last,*next;
	int tid;
	pid_t pid;
	
	int *write_code_to;
	int wflags;
	pid_t who;
	int idtype;
	struct __wrusage *usage;
	struct siginfo_t *siginfo;
} waiters;
class (CWaitEvent) {
	CWaitEvent *last,*next;
	int code;
	pid_t from;
	pid_t parent;
	/* See wait4(2)
	 * Use`d wih P_UID/P_GID/P_SID
	 */
	uid_t uid;
	gid_t gid;
	gid_t sid;
	struct __wrusage usage;
	siginfo_t siginfo;
} wait_events;
#define PIF_PTRACE_FOLLOW_FORK 2
#define PIF_PTRACE_LWP_EVENTS 4
#define PIF_TO_SCX 8
#define PIF_EXITED 32 
#define PIF_TO_SCE 64 
#define PIF_BORN 128
#define PIF_FROZEN 256 //Dont run SCX or do anything on it,someone else (within MrChrootBSD) is ptracin
#define PIF_DONE_WAITING 512
#define PIF_SYSCALL 1024 //ptrace PT_SYSCALL 
/*
 * 21 Nroot here
 * I will end Chrooted strings with "\00\01\02\00"
 * Host Strings will end with "\00\02\01\00"
 * */
#define MC_CHROOTED_ENDING "\00\01\02\00"
#define MC_UNCHROOTED_ENDING "\00\02\01\00"
static char *SetEnding(char *to,const char *which) {
	size_t t=strlen(to);
	memcpy(to+t,which,4);
	return to;
}
static char *GetEnding(char *to,const char *from) {
	size_t t=strlen(from);
	memcpy(to,from+t,4);
	return to;
}
static char *StrCpyWithEnding(char *to,const char *from) {
	size_t t=strlen(from);
	memmove(to,from,t+4);
	return to;
}
static bool is_empty_path(char *a) {
	return 0==*a;
}
static void *GetHackDataAreaForPid();
static int64_t GetChrootedPath(char *to, const char *path);
static int64_t UnChrootPath(char*to,char *from);
static char *C(const char *p) {
	char palidrome[4];
	static char st[1024];
	GetEnding(palidrome,p);
	if(!memcmp(palidrome,MC_CHROOTED_ENDING,4)) {
		return (char*)p;
	}
	if(memcmp(palidrome,MC_UNCHROOTED_ENDING,4)) {
	}
	strcpy(st,p);
	GetChrootedPath(st,st);
	SetEnding(st,MC_CHROOTED_ENDING);
	return st;
}
static char *U(const char*p) {
	char palidrome[4];
	static char st[1024];
	GetEnding(palidrome,p);
	if(!memcmp(palidrome,MC_UNCHROOTED_ENDING,4)) {
		return (char*)p;
	}
	if(memcmp(palidrome,MC_CHROOTED_ENDING,4)) {
	}
	strcpy(st,p);
	SetEnding(st,MC_UNCHROOTED_ENDING);
	UnChrootPath(st,st);
	return st;
}
class (COnSyscallExit) {
	struct COnSyscallExit *next;
	void (*on_exit_cb)(struct COnSyscallExit *);
	int64_t no_continue; //Set this in on_exit_cb
	int64_t ret_code;
	int64_t tid;
	char *restore1;
	char *restore2;
	char *restore3;
	char *restore_ptr1;
	char *restore_ptr2;
	char *restore_ptr3;
	int64_t restore_len1;
	int64_t restore_len2;
	int64_t restore_len3;
	int64_t user_data; /* See notes in UpdateWait */
	int64_t from_syscall; /* Only used with wait and freinds */
	int64_t _use_args[6];
	char error,normal;
};
//Used for ptrace on ptrace(Ran after COnSyscallExit)
// Useful tor running debuggers in MrChrootBSD
class (CPostSyscallExit) {
	struct CPostSyscallExit *next;
	void (*on_post_exit_cb)(struct CPostSyscallExit *);
	char *user_data;
	int64_t dont_remove;
};
//
// Ditto 21
//
class (CPostSyscallEnter) {
	struct CPostSyscallEnter *next;
	void (*on_post_enter_cb)(struct CPostSyscallEnter *);
	char *user_data;
	int64_t dont_remove;
};

class (CProcInfo) {
  CProcInfo *last, *next;
  pid_t pid,parent,debugged_by;
  int wait_for_type,wait_for_id,wait_options;
  CMrChrootHackPtrs *hacks_array_ptr;
  int64_t flags;
  int ptrace_event_mask;
  struct ptrace_lwpinfo lwpinfo;
  int ngrps;
  int saved_status;
  gid_t groups[NGROUPS_MAX+1];
  uid_t uid,suid,euid; //suid==saved gid,[g/s]etresuid 311/312
  gid_t gid,sgid,egid;
  CFDCache *fd_cache;
  CChrootRoot *chrooted_at;
  char *login;
  /* Sometimes we catch a kill(2) signal during a syscall. If we get such a thing,
   * be sure to delegate our kill next time we use PT_CONTINUE(and freinds like PT_TO_SCX)
   * 
   * I made a function called NextKillSig(),use it
   *    - 21 Nroot
  */
  int kill_with_signal;
  COnSyscallExit *sc_on_exit;
  CPostSyscallEnter *sc_post_on_enter;
  CPostSyscallExit *sc_post_on_exit;
} proc_head;
static int64_t ProcIsAlive(pid_t);
static COnSyscallExit *AtSytle(char *, int64_t, int64_t);
static void DelegatePtraceEvent(pid_t who, int code,struct __wrusage *u,siginfo_t *si);
static CProcInfo *GetProcInfByPid(pid_t pid);
static int64_t GetProcCwd(char *to);
static void RemoveProc(pid_t pid);
static int NextKillSig(pid_t pid) {
	CProcInfo *p=GetProcInfByPid(pid);
	int ret=0;
	if(p) {
		ret=p->kill_with_signal;
		p->kill_with_signal=0;
	}
	return ret;
}
static int ptrace2(int a,pid_t p,void *add ,int d) {
	int r=ptrace(a,p,add,d);
	//if(r) printf("%d,%d,%d\n",a,p,errno);
	return r;
}

#define assert(f) if(!(f)) {fprintf(stderr,"Failure at " __FILE__  "(%d). Your on your own!!!\n",__LINE__); abort();}
static pid_t mc_current_pid;
static int mc_current_tid,mc_current_wait_cond; //LWP id
static void OnSyscallExitSetBackup1(COnSyscallExit *e,const char *to,char *a,int64_t l) {
	if(e->restore1) abort();
	e->restore1=calloc(1,l);
	e->restore_ptr1=to;
	e->restore_len1=l;
	memcpy(e->restore1,a,l);
}
static void OnSyscallExitSetBackup2(COnSyscallExit *e,const char *to,char *a,int64_t l) {
	if(e->restore2) abort();
	e->restore2=calloc(1,l);
	e->restore_ptr2=to;
	e->restore_len2=l;
	memcpy(e->restore2,a,l);
}
static void OnSyscallExitSetBackup3(COnSyscallExit *e,const char *to,char *a,int64_t l) {
	if(e->restore3) abort();
	e->restore3=calloc(1,l);
	e->restore_ptr3=to;
	e->restore_len3=l;
	memcpy(e->restore3,a,l);
}
static void PostSC() {
	CProcInfo *pinf=GetProcInfByPid(mc_current_pid);
	struct ptrace_lwpinfo inf;
	ptrace(PT_LWPINFO,mc_current_tid,&inf,sizeof(inf));
	if(inf.pl_flags&PL_FLAG_SCE) {
		CPostSyscallEnter *pe;
		if(pe=pinf->sc_post_on_enter) {
			if(pe->on_post_enter_cb)
			  pe->on_post_enter_cb(pe);
			if(!pe->dont_remove) {
				pinf->sc_post_on_enter=pe->next;
				free(pe);
			}
		}
	}
	if(inf.pl_flags&PL_FLAG_SCX) {
		CPostSyscallExit *pe;
		if(pe=pinf->sc_post_on_exit) {
			if(pe->on_post_exit_cb)
				pe->on_post_exit_cb(pe);
			if(!pe->dont_remove) {
				pinf->sc_post_on_exit=pe->next;
				free(pe);
			}
		}
	}
}
static void PT_SyscallExit() {
	CProcInfo *pinf=GetProcInfByPid(mc_current_pid);
	PostSC();
	if(!(pinf->flags&PIF_FROZEN)) {
	  ptrace(PT_TO_SCX,mc_current_tid,(caddr_t)1,NextKillSig(mc_current_pid));
	}
}
static void PT_SyscallEnter() {
	CProcInfo *pinf=GetProcInfByPid(mc_current_pid);
	PostSC();
	if(!(pinf->flags&PIF_FROZEN)) {
	  ptrace(PT_TO_SCE,mc_current_tid,(caddr_t)1,NextKillSig(mc_current_pid));
	 }
}
static COnSyscallExit *FinishFail(int64_t code) {
	CProcInfo *pinf=GetProcInfByPid(mc_current_pid);
	COnSyscallExit *sce=calloc(1,sizeof(COnSyscallExit));
	sce->error=1;
	sce->ret_code=code;
	sce->tid=mc_current_tid;
	sce->next=pinf->sc_on_exit;
	pinf->sc_on_exit=sce;
	return sce;
}
static COnSyscallExit *FinishPass1(int64_t code) {
	CProcInfo *pinf=GetProcInfByPid(mc_current_pid);
	COnSyscallExit *sce=calloc(1,sizeof(COnSyscallExit));
	sce->error=0;
	sce->ret_code=code;
	sce->tid=mc_current_tid;

	sce->next=pinf->sc_on_exit;
	pinf->sc_on_exit=sce;

	return sce;
}
static COnSyscallExit *FinishPass0() {
	CProcInfo *pinf=GetProcInfByPid(mc_current_pid);
	COnSyscallExit *sce=calloc(1,sizeof(COnSyscallExit));
	sce->error=0;
	sce->ret_code=0;
	sce->tid=mc_current_tid;

	sce->next=pinf->sc_on_exit;
	pinf->sc_on_exit=sce;

	return sce;
}
static  COnSyscallExit *FinishNormal() {
	CProcInfo *pinf=GetProcInfByPid(mc_current_pid);
	COnSyscallExit *sce=calloc(1,sizeof(COnSyscallExit));
	sce->normal=1;
	sce->tid=mc_current_tid;

	sce->next=pinf->sc_on_exit;
	pinf->sc_on_exit=sce;

	return sce;
}

static COnSyscallExit *FinishPass1NoQueue(int64_t code) {
	CProcInfo *pinf=GetProcInfByPid(mc_current_pid);
	COnSyscallExit *sce=calloc(1,sizeof(COnSyscallExit));
	sce->error=0;
	sce->ret_code=code;
	sce->tid=mc_current_tid;

	sce->next=pinf->sc_on_exit;
	pinf->sc_on_exit=sce;

	return sce;
}

static void SetArg(int64_t a,int64_t v) {
	ABISetArg(mc_current_tid,a,v);
}
static int64_t GetArg(int64_t a) {
	return ABIGetArg(mc_current_tid,a);
}
static void SetReturn(int64_t e,int64_t fu) {
	ABISetReturn(mc_current_tid,e,fu);
}
static void SetSyscall(int64_t sc) {
	ABISetSyscall(mc_current_tid,sc);
}
static int64_t GetReturn(char *fail) {
	return ABIGetReturn(mc_current_tid,fail);
}

// Fakes a succeffusl return
static void FakeSuccess() {
	FinishPass0();
}
#define ptrace ptrace2
static long GetKInfoProc(struct kinfo_proc *ret,pid_t p,bool inc_threads) {
	int dummy_name[4];
	size_t r=0;
	dummy_name[0]=CTL_KERN;
	dummy_name[1]=KERN_PROC;
	dummy_name[2]=KERN_PROC_PID;
	dummy_name[3]=p;
	if(inc_threads)
	  dummy_name[2]|=KERN_PROC_INC_THREAD;
	if(sysctl(dummy_name,4,NULL,&r,NULL,0))
		return 0;
	if(r<sizeof(struct kinfo_proc))
	  return 0;
    if(sysctl(dummy_name,4,ret,&r,NULL,0))
      return 0;
	return r;
}
/* clang-format on */
static void RemoveWaitEvent(CWaitEvent *);

static char *StrMove(char *to, char *from) {
  int64_t len = strlen(from) + 1;
  return memmove(to, from, len);
}
int64_t NormailizePath(char *to, const char *path);
static char *ChrootedRealpath(char *to, char *path);
static CChrootRoot *ChrootAt(char *at) {
  CChrootRoot *cur;
  char the_path[1024];
  strcpy(the_path, at);
  for (cur = chroot_root.next; cur != &chroot_root; cur = cur->next) {
    if (!strcmp(cur->root, the_path)) {
      cur->ref_cnt++;
      return cur;
    }
  }
  CChrootRoot *next, *last, *cr = calloc(1, sizeof(CChrootRoot));
  last = &chroot_root;
  next = last->next;
  last->next = cr;
  next->last = cr;
  cr->next = next;
  cr->last = last;
  cur->ref_cnt = 1;
  strcpy(cr->root, the_path);
  return cr;
}
static int64_t UnChrootPath(char *to, char *_from) {
  CProcInfo *pinf = GetProcInfByPid(mc_current_pid);
  char buf[1024], *cur = buf, from[1024],*at;
  CMountPoint *mp, *best = root_mount;
  int64_t trim, best_len = 0, len, prefix;
  sprintf(from, "%s", _from);
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
  memmove(cur, best->src_path, prefix);
  if (to) {
    at=pinf->chrooted_at->root;
    if (strlen(at) < strlen(buf)) {
	  if(at[0]&&at[strlen(at)-1]=='/')
      strcpy(to, buf + strlen(at)-1);
      else
      strcpy(to, buf + strlen(at));
    } else
      strcpy(to, "/");
    SetEnding(to, MC_UNCHROOTED_ENDING);
  }
  return strlen(buf);
}
static struct procstat *ps = NULL;
static int64_t FdToStr(char *to, int fd) {
  int64_t res_cnt = 0;
  strcpy(to, "");
  SetEnding(to, MC_UNCHROOTED_ENDING);
  char buf[1024];
  CProcInfo *pinf = GetProcInfByPid(mc_current_pid);
  if (fd == AT_FDCWD) {
    return GetProcCwd(to);
  }
  char *have;
  if (have = FDCacheGet(pinf->fd_cache, fd)) {
    if (have != FD_CACHE_NOT_FILE) {
      if (to) {
        strcpy(to, have);
        SetEnding(to, MC_UNCHROOTED_ENDING);
        return strlen(have);
      }
    }
  }
  if (!ps)
    ps = procstat_open_sysctl();
  struct filestat_list *head;
  // See /usr/src/use.bin/procstat in FreeBSD
  struct filestat *fs;
  int cnt;
  struct kinfo_file *kfiles = kinfo_getfile(mc_current_pid, &cnt),
                    *kfcur = kfiles;
  FDCacheSet(pinf->fd_cache, fd, FD_CACHE_NOT_FILE);
  for (int i = 0; i < cnt; i++) {
    if (kfcur->kf_type == KF_TYPE_VNODE) {
      if (kfcur->kf_fd == fd) {
        if (strlen(kfcur->kf_path)) {
          strcpy(to, kfcur->kf_path);
          SetEnding(to, MC_UNCHROOTED_ENDING);
          UnChrootPath(buf, to);
          FDCacheSet(pinf->fd_cache, fd, buf);
          break;
        }
      }
    }
    kfcur = (char *)kfcur + kfcur->kf_structsize;
  }
  free(kfiles);
  if (!to[0]) {
  } else {
    UnChrootPath(to, to);
  }
  res_cnt = strlen(to);
  return res_cnt;
}

static int64_t HasChildren(pid_t p) {
  if (!ps)
    ps = procstat_open_sysctl();
  // See /usr/src/use.bin/procstat in FreeBSD
  unsigned cnt = 0, has_child = 0;
  // Savage Mode3
  struct kinfo_proc *kprocs = procstat_getprocs(ps, KERN_PROC_PROC, 0, &cnt);
  for (unsigned i = 0; i < cnt; i++) {
    if (kprocs[i].ki_ppid == p) {
      has_child = 1;
      break;
    }
  }
  procstat_freeprocs(ps, kprocs);
  return has_child;
}
static pid_t GetParent(pid_t p) {
  if (!ps)
    ps = procstat_open_sysctl();
  // See /usr/src/use.bin/procstat in FreeBSD
  pid_t parent = 0;
  unsigned cnt = 0, has_child = 0;
  // Savage Mode3
  struct kinfo_proc *kprocs = procstat_getprocs(ps, KERN_PROC_PID, p, &cnt);
  for (unsigned i = 0; i < cnt; i++) {
    if (kprocs[i].ki_ppid) {
      parent = kprocs[i].ki_ppid;
      break;
    }
  }
  procstat_freeprocs(ps, kprocs);
  return parent;
}
static int64_t GetProcCwd(char *to) {
  unsigned cnt = 0;
  pid_t pid = mc_current_pid;
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
    if (head) {
      STAILQ_FOREACH(fs, head, next) {
        if (fs->fs_path && fs->fs_uflags & PS_FST_UFLAG_CDIR) {
          res_cnt = UnChrootPath(buf, fs->fs_path);
          if (to) {
            strcpy(to, buf);
            SetEnding(to, MC_UNCHROOTED_ENDING);
          }
          break;
        }
      }
      procstat_freefiles(ps, head);
    }
  }
  procstat_freeprocs(ps, kprocs);
  return res_cnt;
}
static void PTraceRestoreBytes(void *pt_ptr, void *backup, size_t len) {
  assert(PTraceWrite(mc_current_tid, pt_ptr, backup, len) == len);
}

static void PTraceWriteBytes(void *pt_ptr, const void *st, size_t len) {
  assert(PTraceWrite(mc_current_tid, pt_ptr, st, len) == len);
}

#define declval(T) (*(T *)0ul)
#define Startswith(s, what) (!memcmp((s), (what), strlen(what)))
static CProcInfo *proc_info_cache[0x10000];
static void OnSyscallExitDel(COnSyscallExit *g) {
  if (!g)
    return;
  OnSyscallExitDel(g->next);
  if (g->restore1)
    free(g->restore1);
  if (g->restore2)
    free(g->restore2);
  if (g->restore3)
    free(g->restore3);
  free(g);
}
static void PostSyscallExitDel(CPostSyscallExit *e) {
  if (!e)
    return;
  PostSyscallExitDel(e->next);
  free(e);
};
static void PostSyscallEnterDel(CPostSyscallEnter *e) {
  if (!e)
    return;
  PostSyscallEnterDel(e->next);
  free(e);
};
static void RemoveProc(pid_t pid) {
  CProcInfo *cur, *next, *last;
  CWaitEvent *wev, *ev_next;
  if (0 <= pid && pid < 0x10000)
    proc_info_cache[pid] = NULL;
  for (cur = proc_head.next; cur != &proc_head; cur = cur->next) {
    if (pid == cur->pid) {
      last = cur->last;
      next = cur->next;
      next->last = last;
      last->next = next;
      FDCacheDel(cur->fd_cache);
      cur->fd_cache = NULL;
      OnSyscallExitDel(cur->sc_on_exit);
      PostSyscallEnterDel(cur->sc_post_on_enter);
      PostSyscallExitDel(cur->sc_post_on_exit);
      free(cur->login);
      free(cur);
      return;
    }
  }
}

static CProcInfo *GetProcInfByPid(pid_t pid) {
  CProcInfo *cur;
  pid_t parent;
  if (0 <= pid && pid < 0x10000)
    if (cur = proc_info_cache[pid])
      return cur;
  for (cur = proc_head.next; cur != &proc_head; cur = cur->next) {
    if (pid == cur->pid) {
      return cur;
    }
  }
  *(cur = calloc(sizeof(*cur), 1)) =
      (CProcInfo){.next = &proc_head,
                  .last = proc_head.last,
                  .pid = pid,
                  .pid = pid,
                  .fd_cache = FDCacheNew(),
                  .ptrace_event_mask = PTRACE_EXEC};
  cur->chrooted_at = ChrootAt("/");
  if (0 <= pid && pid < 0x10000)
    proc_info_cache[pid] = cur;
  return cur->last->next   //
         = cur->next->last //
         = cur;
}

static int64_t ProcIsAlive(pid_t pid) {
  CProcInfo *cur;
  if (-1 == getpgid(pid))
    return 0;
  return 1;
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
  if (options & WEXITED)
    if (WIFEXITED(what))
      return 1;
  if (WIFSTOPPED(what)) {
    if (options & WUNTRACED) {
      switch (WSTOPSIG(what)) {
      case SIGTTIN:
      case SIGTTOU:
      case SIGTSTP:
      case SIGSTOP:
        return 1;
      default:
        return 0;
      }
    }
    return 1;
  }
  if (options & WSTOPPED)
    if (WIFSTOPPED(what))
      return 1;
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
static pid_t ToPid(pid_t pid) {
	CProcInfo *pinf=proc_head.next;
	pid_t tids[0x10000];
	int tid_cnt;
	for(;pinf!=&proc_head;pinf=pinf->next) {
		if(pinf->pid==pid) {
			return pid;
		}
	}
	for(pinf=proc_head.next;pinf!=&proc_head;pinf=pinf->next) {
		tid_cnt=ptrace(PT_GETNUMLWPS,pinf->pid,0,0);
		tid_cnt=ptrace(PT_GETLWPLIST,pinf->pid,(caddr_t)&tids,tid_cnt*sizeof(pid_t));
		while(--tid_cnt>=0) {
			if(tids[tid_cnt]==pid) {
				return pinf->pid;
			}
		}
	}
	return pid; //Man what
}
static void Freeze(pid_t pid) {
	CProcInfo *pinf=GetProcInfByPid(ToPid(pid));
	pinf->flags|=PIF_FROZEN;
}
static void UnFreesze(pid_t pid) {
	CProcInfo *pinf=GetProcInfByPid(ToPid(pid));
	pinf->flags&=~PIF_FROZEN;
}
static void FabricateSiginfoSIGCHLD(siginfo_t *si) {
	CProcInfo *pinf=GetProcInfByPid(mc_current_pid);
	memset(si,0,sizeof *si);
	si->si_signo=SIGCHLD;
	si->si_code=CLD_TRAPPED;
	si->si_uid=pinf->uid;
	si->si_pid=mc_current_pid;
	si->si_status=SIGTRAP;
}
static void PtraceDumbSCE(CPostSyscallEnter *pe) {
	CProcInfo *pinf=GetProcInfByPid(mc_current_pid);
	siginfo_t si;
	FabricateSiginfoSIGCHLD(&si);
	if(pinf->debugged_by) {
			kill(pinf->debugged_by,SIGCHLD);
			DelegatePtraceEvent(mc_current_pid,_WSTOPPED|(SIGTRAP<<8),NULL,&si);
			Freeze(mc_current_pid);
	}
}
static void PtraceDumbSCX(CPostSyscallExit *pe) {
	CProcInfo *pinf=GetProcInfByPid(mc_current_pid);
	siginfo_t si;
	FabricateSiginfoSIGCHLD(&si);
	if(pinf->debugged_by) {
			kill(pinf->debugged_by,SIGCHLD);
			DelegatePtraceEvent(mc_current_pid,_WSTOPPED|(SIGTRAP<<8),NULL,&si);
			Freeze(mc_current_pid);
	}
}
static void InterceptPtrace() {
  CPostSyscallEnter *pse;
  CPostSyscallExit *psx;
  pid_t pid = mc_current_pid;
  int req = GetArg(0);
  pid_t who = GetArg(1);
  void *addr = (void *)GetArg(2);
  int64_t data = GetArg(3), ret = 0;
  CProcInfo *pinf;
  int failed = 0;
  switch (req) {
  case PT_TRACE_ME:
    pinf = GetProcInfByPid(mc_current_pid);
    SetSyscall(
        20); // Run *getpid* instread of ptrace(dont run ptrace on ptrace)
    pinf->debugged_by = pinf->parent;
    pinf->ptrace_event_mask = PL_FLAG_EXEC;
    break;
  case PT_CONTINUE:
continue_style:
	SetSyscall(
        20 // Run *getpid* instread of ptrace(dont run ptrace on ptrace)
    );
    //printf("COPNT:%d,%d\n",addr,data);
    if(req==PT_KILL) {
		ptrace(PT_KILL,who,addr,data);
	} else if(req==PT_STEP)
		ptrace(PT_STEP,who,addr,data);
		else if(req==PT_SYSCALL)
		ptrace(PT_SYSCALL,who,addr,data);
	else 
		ptrace(PT_TO_SCE,who,addr,data);
		UnFreesze(who);
    FinishPass0();
    break;
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
	goto continue_style;
  case PT_KILL:
	goto continue_style;
  case PT_ATTACH:
  case PT_DETACH:
    goto use_host_ptrace;
  case PT_GETREGSET:
  case PT_SETREGSET:
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
    else if(req==PT_GETLWPLIST)
		data = sizeof(struct ptrace_lwpinfo);
    // Write into poo poo tasks addres space
    void *dumb = calloc(1, data + sizeof(struct ptrace_lwpinfo));
    ret = ptrace(req, who, dumb, data);
    if (ret == -1) {
      ret = -errno;
      failed = 1;
    }
    if(req==PT_GETLWPLIST) {
	}
    if (req == PT_LWPINFO) {
      struct ptrace_lwpinfo *inf = dumb;
      CProcInfo *dpinf = GetProcInfByPid(mc_current_pid);
      pinf = GetProcInfByPid(mc_current_pid);
    }
    PTraceWriteBytes(addr, dumb, data);
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
  
    goto use_host_ptrace;
  case PT_RESUME:
    ret=0;
    failed=0;	
	goto intercept;
  case PT_SYSCALL:
    pinf=GetProcInfByPid(mc_current_pid);
    pinf->flags|=PIF_SYSCALL;
    if(pinf->sc_post_on_exit||pinf->sc_post_on_enter) {
		goto continue_style;
	}
    
    psx=calloc(1,sizeof (CPostSyscallExit));
    pinf = GetProcInfByPid(ToPid(who));
    psx->next=pinf->sc_post_on_exit;
    pinf->sc_post_on_exit=psx;
    psx->on_post_exit_cb=&PtraceDumbSCX;
	psx->dont_remove=1;
	
	pse=calloc(1,sizeof (CPostSyscallEnter));
    pinf = GetProcInfByPid(ToPid(who));
    pse->next=pinf->sc_post_on_enter;
    pinf->sc_post_on_enter=pse;
    pse->on_post_enter_cb=&PtraceDumbSCE;
	pse->dont_remove=1;
	
    goto continue_style;
  case PT_TO_SCE:
    pse=calloc(1,sizeof (CPostSyscallEnter));
    pinf = GetProcInfByPid(ToPid(who));
    pse->next=pinf->sc_post_on_enter;
    pinf->sc_post_on_exit=pse;
    pse->on_post_enter_cb=&PtraceDumbSCE;
    pinf->flags|=PIF_TO_SCE;
    FinishPass0();
	break;
  case PT_TO_SCX:
    psx=calloc(1,sizeof (CPostSyscallExit));
    pinf = GetProcInfByPid(ToPid(who));
    psx->next=pinf->sc_post_on_exit;
    pinf->sc_post_on_exit=psx;
    psx->on_post_exit_cb=&PtraceDumbSCX;
    pinf->flags|=PIF_TO_SCX;
    FinishPass0();
	break;
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
  case PT_SETFPREGS:
  case PT_SETDBREGS:
  case PT_SETGSBASE:
  case PT_SETREGS:
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
    void *dumb = calloc(1, data);
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
    failed = 0;
    if (req == PT_READ_D || req == PT_READ_I)
      ret = ptrace(req, who, addr, data);
    else {
      ret = ptrace(req, who, addr, data);
    }
  intercept:
    SetSyscall(
        20); // Run *getpid* instread of ptrace(dont run ptrace on ptrace)
    COnSyscallExit *osce;
    if (failed)
      osce = FinishFail(ret);
    else {
      osce = FinishPass1(ret);
    }
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
static int IsParentProc(pid_t a, pid_t b) {
  CProcInfo *cur = GetProcInfByPid(b);
  return cur->parent == a;
}
static CWaitEvent *EventForWait(pid_t pid, pid_t who, int _idtype) {
  CWaitEvent *wev;
  CProcInfo *pinfw = NULL;
  CProcInfo *pinfp = NULL;
  for (wev = wait_events.next; wev != &wait_events; wev = wev->next) {
    int is_parent = IsParentProc(pid, wev->from) || pid == wev->parent;
    if (_idtype == 0) {
      if (who == -1 && is_parent) { // Any child
        return wev;
      }
      if (who > 0) {
        if (wev->from == who)
          return wev;
      }
      if (who < -1) {
        if (getpgid(wev->from) == -who)
          return wev;
      }
      if (who == 0 && is_parent) {
        if (getpgid(wev->from) == getpgid(pid)) {
          return wev;
        }
      }
    }
    if (_idtype == P_PID) {
      if (wev->from == who && is_parent)
        return wev;	
    }
    if (_idtype == P_PGID) {
      if (getpgid(wev->from) == who && is_parent)
        return wev;
    }
    if (_idtype == P_ALL && is_parent) {
      return wev;
    }
    if (_idtype == P_SID) {
      if (wev->sid == who)
        return wev;
    }
    if (_idtype == P_GID) {
      if (wev->gid == who)
        return wev;
    }
    if (_idtype == P_UID) {
      if (wev->uid == who)
        return wev;
    }
  }
  return NULL;
}
static void *SCRemoteNoBlock(void *s) {
  COnSyscallExit *osce = s;
  struct ptrace_sc_remote rmt;
  memset(&rmt, 0, sizeof rmt);
  rmt.pscr_syscall = 7;
  rmt.pscr_nargs = 4;
  rmt.pscr_args = osce->_use_args;
  ptrace(PT_SC_REMOTE, osce->tid, &rmt, sizeof(rmt));
  return NULL;
}
static void UpdateWait(COnSyscallExit *un) {
  char use_delegated = 1;
  COnSyscallExit *osce;
  CProcInfo *cur, *cur2;
  CTidWait *waiter, *next_waiter;
  CWaitEvent *wev;
  int *write_code_to, who, wflags;
  int64_t args4[4];
  int tid, pass;
  char failed, interupt;
  CProcInfo *pinf;
  struct ptrace_lwpinfo inf;
  ptrace(PT_LWPINFO, mc_current_tid, (caddr_t)&inf, sizeof inf);
  for (waiter = waiters.next; waiter != &waiters; waiter = next_waiter) {
    next_waiter = waiter->next;
    cur = GetProcInfByPid(waiter->pid);
    tid = waiter->tid;
    pass = 0;
    if (cur->pid != mc_current_pid)
      goto next;
    write_code_to = waiter->write_code_to;
    wflags = waiter->wflags;
    who = waiter->who;
  wait4:;
    if (wev = EventForWait(cur->pid, who, waiter->idtype)) {
      osce=FinishPass1(wev->from);
      if(write_code_to)
          OnSyscallExitSetBackup2(osce, write_code_to, &wev->code, sizeof(int));
      if(waiter->siginfo)
		    OnSyscallExitSetBackup3(osce, waiter->siginfo, &wev->siginfo, sizeof(struct __wrusage));
      if(waiter->usage)
		    OnSyscallExitSetBackup1(osce, waiter->usage, &wev->usage, sizeof(siginfo_t));
	  pinf=GetProcInfByPid(mc_current_pid);
	  pinf->flags|=PIF_DONE_WAITING;
      pass = 1;
      goto next;
    }
    if (!HasChildren(cur->pid)) {
      FinishFail(-ECHILD);
      pinf=GetProcInfByPid(mc_current_pid);
	  pinf->flags|=PIF_DONE_WAITING;
      goto remove_waiter;
    }
    // if WNOHANG was set,return as usale
    if (wflags & WNOHANG) {
      pass = 1;
      FinishPass1(0);
      pinf=GetProcInfByPid(mc_current_pid);
	  pinf->flags|=PIF_DONE_WAITING;
      goto next;
    }
  next:;
    if (pass) {
		if (wev && !(wflags & WNOWAIT))
        RemoveWaitEvent(wev);
    remove_waiter:
      waiter->next->last = waiter->last;
      waiter->last->next = waiter->next;
      free(waiter);
      return;
    }
  }
real:;
}
static void DelegatePtraceEvent(pid_t who, int code,struct __wrusage *u,siginfo_t *si) {
  if (who) {
    CWaitEvent *ev = calloc(1, sizeof(CWaitEvent)), *tmp;
    CProcInfo *inf = GetProcInfByPid(who);
    ev->from = who;
    ev->parent = inf->parent;
    ev->code = code;
    ev->uid = inf->euid;
    ev->gid = inf->egid;
    ev->sid = getsid(who);
    ev->last = wait_events.last;
    ev->next = &wait_events;
    ev->next->last = ev;
    ev->last->next = ev;
    if(u)
		ev->usage=*u;
    if(si)
		ev->siginfo=*si;
  }
  pid_t oldp = mc_current_pid, oldt = mc_current_tid;
  CTidWait *cur;
  for (cur = waiters.next; cur != &waiters; cur = cur->next) {
    mc_current_pid = cur->pid;
    mc_current_tid = cur->tid;
    UpdateWait(NULL);
  }
  mc_current_pid = oldp;
  mc_current_tid = oldt;
}
// Returns 1 if unpaused,else 0
static int InterceptWait(int six,int who, int *write_to, int wflags,struct __wrusage *usage,siginfo_t *si) {
  CProcInfo *inf = GetProcInfByPid(mc_current_pid);
  CTidWait *waiter = calloc(1, sizeof(CTidWait));
  waiter->tid = mc_current_tid;
  waiter->pid = mc_current_pid;

  waiter->wflags = wflags;
  if (write_to)
    waiter->write_code_to = write_to;
  else
    waiter->write_code_to = GetHackDataAreaForPid(who);
  waiter->who = who;
  waiter->usage=usage;
  waiter->siginfo=si;

  waiter->next = waiters.next;
  waiter->last = &waiters;
  waiter->last->next = waiter;
  waiter->next->last = waiter;
  waiter->idtype=0;

  if(six==6) {
	SetArg(3, wflags | WNOHANG);
	waiter->idtype=GetArg(0);
  } else
	SetArg(2, wflags | WNOHANG);
  UpdateWait(NULL);
  return 0;
}

int64_t NormailizePath(char *to, const char *path) {
  int64_t idx;
  char palidrome[4];
  char result[1024];
  strcpy(result, path);
  GetEnding(palidrome, path);
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
  if (to) {
    strcpy(to, result);
    SetEnding(to, palidrome);
  }
  return strlen(result);
}
static int64_t GetChrootedPath0(char *to, const char *path,
                                CMountPoint **have_mp) {

  pid_t pid = mc_current_pid;
  CProcInfo *pinf = GetProcInfByPid(pid);
  int64_t idx;
  size_t max_match = 0, len;
  char result[1024];
  char s[1024], *cur = s;
  CMountPoint *mp, *choose=NULL;
  if (*path == '/') {
    if (pinf->chrooted_at->root[0]) {
      strcpy(result, pinf->chrooted_at->root);
      strcat(result, "/");
    } else
      strcpy(result, "/");
  } else {
    // TODO prevent root escape
    GetProcCwd(result);
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

  if (to) {
    strcpy(to, s);
    SetEnding(to, MC_CHROOTED_ENDING);
  }
  return strlen(s);
}
static int64_t GetChrootedPath(char *to, const char *path) {
  return GetChrootedPath0(to, path, NULL);
}
char *DatabasePathForFile(char *to, const char *path) {
  CMountPoint *mp = NULL;
  char dummy[1024];
  path = U(path);
  GetChrootedPath0(dummy, path, &mp);
  if (!mp->document_perms)
    return NULL;
  sprintf(to, "%s/%s/%s", mp->db_path,
          GetProcInfByPid(mc_current_pid)->chrooted_at->root,
          dummy + strlen(mp->dst_path));
  SetEnding(to, MC_UNCHROOTED_ENDING);
  NormailizePath(to, to);
  return to;
};
static char *ChrootedRealpath(char *to, char *path) {
  char dst[1024];
  path = C(path);
  UnChrootPath(to, path);
  return to;
}
static uint32_t FilePerms(char *fn) {
  CHashEntry dummy;
  if (HashTableGet(&dummy, fn)) {
    return dummy.perms;
  }
  return 0755; //??? TODO test if dir or file
}
static void ChrootDftOwnership(char *pa) {
  char dst[1024];
  CProcInfo *inf = GetProcInfByPid(mc_current_pid);
  ChrootedRealpath(dst, pa);
  HashTableSet(dst, inf->uid, inf->gid, FilePerms(dst));
}
static ptrdiff_t ReadPTraceString(char *to, char *pt_ptr) {
  pid_t pid = mc_current_pid;
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
static size_t WritePTraceString(void *backup, void *pt_ptr, char const *st) {
  pid_t pid = mc_current_pid;
  size_t len = strlen(st) + 1;
  if (backup)
    assert(PTraceRead(mc_current_tid, backup, pt_ptr, len) == len);
  assert(PTraceWrite(mc_current_tid, pt_ptr, st, len) == len);
  return len;
}

#define INTERCEPT_FILE1(arg)                                                   \
  char backupstr[1024];                                                        \
  char have_str[1024], chroot[1023];                                           \
  int64_t backup_len;                                                          \
  void *orig_ptr, *use;                                                        \
  orig_ptr = (void *)GetArg(arg);                                              \
  ReadPTraceString(have_str, orig_ptr);                                        \
  SetEnding(have_str, MC_UNCHROOTED_ENDING);                                   \
  use = C(have_str);                                                           \
  backup_len = WritePTraceString(backupstr, orig_ptr, use);                    \
  COnSyscallExit *osce = FinishNormal();                                       \
  OnSyscallExitSetBackup1(osce, orig_ptr, backupstr, backup_len);

#define INTERCEPT_FILE1_ONLY_ABS(arg)                                          \
  char backupstr[1024];                                                        \
  char have_str[1024], chroot[1023];                                           \
  int64_t backup_len;                                                          \
  void *orig_ptr, *use;                                                        \
  orig_ptr = (void *)GetArg(arg);                                              \
  ReadPTraceString(have_str, orig_ptr);                                        \
  SetEnding(have_str, MC_UNCHROOTED_ENDING);                                   \
  if (have_str[0] == '/') {                                                    \
    use = C(have_str);                                                         \
    backup_len = WritePTraceString(backupstr, orig_ptr, use);                  \
    COnSyscallExit *osce = FinishNormal();                                     \
    OnSyscallExitSetBackup1(osce, orig_ptr, backupstr, backup_len);            \
  } else {                                                                     \
    FinishNormal();                                                            \
  }

static void InterceptRealPathAt() {
  pid_t pid = mc_current_pid;
  char have_str[1024], chroot[1024], real[1024];
  void *orig_ptr, *to_ptr;
  to_ptr = (void *)GetArg(2);
  size_t blen = GetArg(3);
  COnSyscallExit *osce = AtSytle(chroot, 0, 1);
  realpath(chroot, real);
  UnChrootPath(chroot, real);
  OnSyscallExitSetBackup2(osce, to_ptr, chroot, strlen(chroot) + 1);
}
static void InterceptChown() {
  pid_t pid = mc_current_pid;
  CProcInfo *inf = GetProcInfByPid(pid);
  char have[1024], c[1024], failed, *use;
  uid_t u = GetArg(1);
  gid_t g = GetArg(2);
  ReadPTraceString(have, (char *)GetArg(0));
  SetEnding(have, MC_UNCHROOTED_ENDING);
  {
    INTERCEPT_FILE1(0);
    osce->normal = 0;
  }
  // TODO PERM CHECK
  HashTableSet(have, u, g, FilePerms(have));
}
#define PERM_WHAT_X 0b001
#define PERM_WHAT_W 0b010
#define PERM_WHAT_R 0b100

// Returns 0 if yat,else -errno
static int HasPerms(int af, char *path_) {
  char path[1024], *use;
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
  pid_t p = mc_current_pid;
  CProcInfo *inf = GetProcInfByPid(mc_current_pid);
  int ngrps = inf->ngrps;
  gid_t *groups = inf->groups;
  int cnt = 0;
  CHashEntry *e, dummy;
  StrCpyWithEnding(dst, C(path_));
  StrCpyWithEnding(uc, U(dst));

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
      // Handle /a/b/c/d/ (with trailing '/')
      if (at && dir[at - 1] == '/')
        dir[at - 1] = 0;
      while (--at >= 0) {
        if (dir[at] == '/') {
          dir[at] = 0;
          break;
        }
      }
      SetEnding(dir, MC_UNCHROOTED_ENDING);
      if (dir[0] != 0)
        return HasPerms(F_OK | af, dir);
    }
  }
  if (e = HashTableGet(&dummy, uc)) {
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
    if (inf->euid == 0)
      /* root?*/
      return 0;
    return -EACCES;
  }
  return 0; //???
}

static void InterceptAccess() {
  int passed;
  char r, failed;
  char what[1024], have[1024];
  {
    INTERCEPT_FILE1(0);
  }
}
static void DupFD(COnSyscallExit *osce) {
  CProcInfo *pinf = GetProcInfByPid(mc_current_pid);
  char *have;
  char fail;
  int fd = GetReturn(&fail);
  if (!fail) {
    if (have = FDCacheGet(pinf->fd_cache, osce->user_data))
      FDCacheSet(pinf->fd_cache, fd, have);
  }
}
static void DupFD2(COnSyscallExit *osce) {
  CProcInfo *pinf = GetProcInfByPid(mc_current_pid);
  char *have;
  char fail;
  int fd = GetReturn(&fail);
  if (!fail) {
    if (have = FDCacheGet(pinf->fd_cache, osce->user_data & 0xffFFffFFul))
      FDCacheSet(pinf->fd_cache, ((uint64_t)osce->user_data) >> 32, have);
  }
}

static void OpenFD(COnSyscallExit *osce) {
  CProcInfo *pinf = GetProcInfByPid(mc_current_pid);
  char have_str[1024];
  // Hack alert,on_exit_cb is called after strings are restored(Chrooted strings
  // are restored into unchrooted ones)
  ReadPTraceString(have_str, (char *)osce->user_data);
  char fail;
  int fd = GetReturn(&fail);
  if (!fail)
    FDCacheSet(pinf->fd_cache, fd, have_str);
}
static void InterceptOpen() {
  CProcInfo *inf = GetProcInfByPid(mc_current_pid);
  int64_t fd, flags = GetArg(1);
  char failed;
  char *orig_ptr = (char *)GetArg(0);
  char have_str[1024], chroot[1024];
  ReadPTraceString(have_str, orig_ptr);
  SetEnding(have_str, MC_UNCHROOTED_ENDING);
  {
    INTERCEPT_FILE1(0);
    osce->user_data = (int64_t)orig_ptr;
    osce->on_exit_cb = &OpenFD;
  }
  if (flags & O_CREAT)
    ChrootDftOwnership(have_str);
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

static void *PTraceReadPtr(void *at) {
  void *ret;
  assert(PTraceRead(mc_current_tid, &ret, at, 8) == 8);
  return ret;
}

static void PTraceWritePtr(void *at, void *ptr) {
  assert(PTraceWrite(mc_current_tid, at, &ptr, 8) == 8);
}
static void *GetHackDataAreaForPid() {
  CProcInfo *pinf = GetProcInfByPid(mc_current_pid);
  return PTraceReadPtr(&pinf->hacks_array_ptr->data_zone);
}

// Returns end of written data
static char *RewriteEnv(char **prog_env, char *data_ptr) {
  int64_t idx, idx2, argc = 0;
  char *arg;
  char val[4048];
  char chrooted[4048], orig[4048], final[4048];
  for (idx = 0; arg = PTraceReadPtr(prog_env + idx); idx++)
    argc++;
  char *new_env_ptrs[argc];
  for (idx = 0; arg = PTraceReadPtr(prog_env + idx); idx++) {
#define LD_LIBRARY_PATH_EQ "LD_LIBRARY_PATH="
    ReadPTraceString(val, arg);
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
      GetChrootedPath(chrooted, orig);
      strcpy(final + strlen(final), chrooted);
      if (*end == ':') {
        strcpy(final + strlen(final), ":");
        start = end + 1;
        goto again;
      }
      WritePTraceString(NULL, data_ptr, final);
      new_env_ptrs[idx] = data_ptr;
      PTraceWritePtr(new_env_ptrs[idx], prog_env + idx);
      data_ptr += strlen(final) + 1;
    } else {
      new_env_ptrs[idx] = arg;
    }
  }
  return data_ptr;
}
static uid_t FileUid(const char *path);
static gid_t FileGid(const char *path);
static void InterceptExecve() {
  char have_str[1024], chroot[1024], backup[1024], poop_ant[1024];
  char *orig_ptr, **argv, **env;
  char *ptr, *ptr2, *command, *argument, *use;
  int64_t fd, args[3], bulen, extra_args = 0, perms;
  bool is_set_uid = false;
  bool is_set_gid = false;
  struct ptrace_sc_remote rmt = {0};
  CProcInfo *pinf = GetProcInfByPid(mc_current_pid);
  orig_ptr = (void *)GetArg(0);
  argv = (void *)GetArg(1);
  env = (void *)GetArg(2);
  ReadPTraceString(have_str, orig_ptr);
  SetEnding(have_str, MC_UNCHROOTED_ENDING);
  GetChrootedPath(chroot, have_str);
  perms = FilePerms(have_str);
  is_set_uid = !!(perms & S_ISUID);
  is_set_gid = !!(perms & S_ISGID);
  memset(poop_ant, 0, sizeof(poop_ant));
  if (!CheckShebang(chroot, poop_ant)) {
    char *tmp1, *tmp2;
    // exeve(open(chrooted),argv,env)
    SetSyscall(5); // iopen
    SetArg(1, O_EXEC);
    ReadPTraceString(poop_ant, orig_ptr);
    SetEnding(poop_ant, MC_UNCHROOTED_ENDING);
    GetChrootedPath(chroot, poop_ant);
    bulen = WritePTraceString(backup, orig_ptr, chroot);
    ptrace(PT_TO_SCX, mc_current_tid, (caddr_t)1, 0);
    waitpid(mc_current_pid, NULL, 0);
    PTraceRestoreBytes(orig_ptr, backup, bulen);
    args[0] = GetReturn(NULL);
    args[1] = (int64_t)argv;
    args[2] = (int64_t)env;
    int64_t i;
    char *av;
    for (i = 0; av = PTraceReadPtr(argv + i); i++) {
      char ass[1023];
      PTraceRead(mc_current_tid, ass, av, 1024);
    }
    rmt.pscr_syscall = 492;
    rmt.pscr_nargs = 3;
    rmt.pscr_args = args;
    RewriteEnv(env, GetHackDataAreaForPid());
    if (is_set_uid)
      pinf->euid = FileUid(have_str);
    if (is_set_gid)
      pinf->egid = FileGid(have_str);
    ptrace(PT_SC_REMOTE, mc_current_tid, (caddr_t)&rmt, sizeof rmt);
    waitpid(mc_current_tid, NULL, 0);
  } else {
    char extra_arg_strs[1024][256];
    // fexecve(open("interrepret name"),argv,env)
    command = SkipWhitespace(poop_ant);
    ptr2 = command;
    while (*ptr2 && !isblank(*ptr2))
      ptr2++;
    *ptr2++ = 0;
    GetChrootedPath(chroot, command);
    SetSyscall(5);
    SetArg(1, O_EXEC);
    bulen = WritePTraceString(backup, orig_ptr, chroot);
    ptrace(PT_TO_SCX, mc_current_tid, (caddr_t)1, 0);
    waitpid(mc_current_pid, NULL, 0);
    PTraceRestoreBytes(orig_ptr, backup, bulen);
    extra_args = 0;
    WritePTraceString(NULL, ptr, command);
    strcpy(extra_arg_strs[extra_args++], command);
    ptr += strlen(command) + 1;
    while (*ptr2) {
      ptr2 = SkipWhitespace(ptr2);
      argument = ptr2;
      while (*ptr2 && !isblank((unsigned char)*ptr2))
        ptr2++;
      *ptr2++ = 0;
      strcpy(extra_arg_strs[extra_args++], argument);
      ptr += strlen(argument) + 1;
    }

    // IF we have '#! /bin/tcsh -xv' in ./poop.sh, do
    // argv[0] = bin/tcsh
    // argv[1] = -xv
    // argv[2] = ./poop.s
    // argv[...] = ...

    // Put command name here
    strcpy(extra_arg_strs[extra_args++], have_str);
    ptr += strlen(have_str) + 1;

    // The first argument to the argv is the program name,but we delegated
    // it to the interrepter REMOVE THE FIRST ARGUMENT AS IT IS UNECESARY
    fd = 0;
    while (PTraceReadPtr(argv + fd + 1)) {
      ReadPTraceString(extra_arg_strs[extra_args++],
                       PTraceReadPtr(argv + fd + 1));
      fd++;
    }

    char *spots[256];
    ptr = orig_ptr;
    for (fd = 0; fd != extra_args; fd++) {
      WritePTraceString(NULL, ptr, extra_arg_strs[fd]);
      spots[fd] = ptr;
      ptr += strlen(extra_arg_strs[fd]) + 1;
    }
    argv = ptr;
    for (fd = 0; fd != extra_args; fd++) {
      PTraceWritePtr(ptr, spots[fd]);
      ptr += sizeof(char *);
    }
    PTraceWritePtr(ptr, NULL);
    ptr += sizeof(char *);

    args[0] = GetReturn(NULL);
    args[1] = (int64_t)argv;
    args[2] = (int64_t)env;
    rmt.pscr_syscall = 492;
    rmt.pscr_nargs = 3;
    rmt.pscr_args = args;
    RewriteEnv(env, ptr);
    if (is_set_uid)
      pinf->euid = FileUid(have_str);
    if (is_set_gid)
      pinf->egid = FileGid(have_str);
    ptrace(PT_SC_REMOTE, mc_current_tid, (caddr_t)&rmt, sizeof rmt);
    waitpid(mc_current_tid,NULL,0);
  }
  if (perms & S_ISUID) {
    pinf->euid = FileUid(have_str);
  }
  if (perms & S_ISGID) {
    pinf->egid = FileGid(have_str);
  }
}

static void InterceptReadlink() {
  char new_path[1024], got_path[1024], backup[1024];
  char rlbuf[1024], *use;
  int64_t backup_len, r, buf_len = GetArg(2);
  void *orig_ptr = (void *)GetArg(0), *buf_ptr = (void *)GetArg(1);
  ReadPTraceString(got_path, orig_ptr);
  SetEnding(got_path, MC_UNCHROOTED_ENDING);
  use = C(got_path);
  backup_len = WritePTraceString(backup, orig_ptr, use);
  COnSyscallExit *osce = FinishNormal();
  OnSyscallExitSetBackup1(osce, orig_ptr, backup, backup_len);
}

#define INTERCEPT_FILE2(arg1, arg2)                                            \
  char backup1[1024], chroot1[1024], got1[1024];                               \
  char backup2[1024], chroot2[1024], got2[1024];                               \
  void *orig_ptr1 = (void *)GetArg(arg1);                                      \
  void *orig_ptr2 = (void *)GetArg(arg2);                                      \
  char *dumb_ptr =                                                             \
      orig_ptr1; /*write 2 strings to  1 pointer in case orig_ptr1/orig_ptr2   \
                    overlap(chrooted strings are larger than originals)*/      \
  int64_t backup_len1, backup_len2;                                            \
  ReadPTraceString(got1, orig_ptr1);                                           \
  ReadPTraceString(got2, orig_ptr2);                                           \
  SetEnding(got1, MC_UNCHROOTED_ENDING);                                       \
  SetEnding(got2, MC_UNCHROOTED_ENDING);                                       \
  StrCpyWithEnding(chroot1, C(got1));                                          \
  StrCpyWithEnding(chroot2, C(got2));                                          \
  /*                                                                           \
  * [chroot1\0chroot2\0]                                                       \
  *           ^                                                                \
  *          |                                                                 \
            + Arg1 is here*/                                                   \
  dumb_ptr = orig_ptr1;                                                        \
  backup_len1 = WritePTraceString(backup1, orig_ptr1, chroot1);                \
  dumb_ptr += backup_len1;                                                     \
  backup_len2 = WritePTraceString(backup2, dumb_ptr, chroot2);                 \
  SetArg(1, (int64_t)dumb_ptr); /*Re-assign poo poo address*/                  \
  COnSyscallExit *osce = FinishNormal();                                       \
  OnSyscallExitSetBackup1(osce, orig_ptr1, backup1, backup_len1);              \
  OnSyscallExitSetBackup2(osce, dumb_ptr, backup2, backup_len2);

static void InterceptLink() {
  char name[1024];
  char failed;
  CProcInfo *inf = GetProcInfByPid(mc_current_pid);
  int64_t r;
  ReadPTraceString(name, (char *)GetArg(0));
  SetEnding(name, MC_UNCHROOTED_ENDING);
  {
    INTERCEPT_FILE2(0, 1);
  }
  ChrootDftOwnership(name);
}

static void InterceptUnlink() {
  INTERCEPT_FILE1(0); // TODO remove hash table }
}
static void InterceptShmRename() { INTERCEPT_FILE2(0, 1); }

static void InterceptChdir() {
  char backupstr[1024];
  char have_str[1024], chroot[1023], *use;
  int64_t backup_len;
  void *orig_ptr;
  orig_ptr = (void *)GetArg(0);
  ReadPTraceString(have_str, orig_ptr);
  SetEnding(have_str, MC_UNCHROOTED_ENDING);
  StrCpyWithEnding(chroot, C(have_str));
  backup_len = WritePTraceString(backupstr, orig_ptr, chroot);
  COnSyscallExit *osce = FinishNormal();
  OnSyscallExitSetBackup1(osce, orig_ptr, backupstr, backup_len);
}

static void Intercept__Getcwd() {
  int64_t olen, cap;
  void *orig_ptr;
  char cwd[1024];
  olen = GetProcCwd(cwd);
  orig_ptr = (void *)GetArg(0);
  cap = GetArg(1);
  COnSyscallExit *osce = FinishPass0();
  OnSyscallExitSetBackup1(osce, orig_ptr, cwd, cap > olen + 1 ? olen + 1 : cap);
}

static void InterceptChmod() {
  char have[1024], real[1024], failed;
  uint32_t perms = GetArg(1);
  ReadPTraceString(have, (char *)GetArg(0));
  SetEnding(have, MC_UNCHROOTED_ENDING);
  {
    INTERCEPT_FILE1(0);
  }
  ChrootedRealpath(real, have);
  HashTableSet(real, FileUid(real), FileGid(real), perms);
}

static void InterceptSetuid() {
  pid_t pid = mc_current_pid;
  CProcInfo *inf = GetProcInfByPid(pid);
  uid_t want = GetArg(0);
  // Sets only if inf->ruid==root||(inf->suid==want||inf->euid==want)
  if (inf->uid == 0) {
  pass:
    inf->suid = inf->euid = inf->uid = want;
  } else if (inf->suid == want || inf->euid == want) {
    goto pass;
  }
  // TODO failure
  FakeSuccess();
}
static void InterceptSeteuid() {
  pid_t pid = mc_current_pid;
  CProcInfo *inf = GetProcInfByPid(pid);
  uid_t want = GetArg(0);
  if (inf->uid == 0) {
  pass:
    inf->euid = want;
  } else if (inf->suid == want || inf->euid == want) {
    goto pass;
  }
  // TODO success
  FakeSuccess();
}
static void InterceptGetuid() {
  pid_t pid = mc_current_pid;
  CProcInfo *inf = GetProcInfByPid(pid);
  FinishPass1(inf->uid);
}

static void InterceptGeteuid() {
  pid_t pid = mc_current_pid;
  CProcInfo *inf = GetProcInfByPid(pid);
  FinishPass1(inf->euid);
}
static void InterceptMount() {}

static void InterceptUnmount() {}

static void InterceptNmount() {}

static void InterceptAccessShmUnlink() { INTERCEPT_FILE1(0); }

static void InterceptAccessTruncate() { INTERCEPT_FILE1(0); }

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
static void InterceptFstat() {
  uid_t dummyu = 0;
  gid_t dummyg = 0;
  uint32_t perms = 0755;
  struct stat st;
  uint8_t *ptr = (void *)GetArg(1);
  char who[1024];
  if (FdToStr(who, GetArg(0))) {
    dummyu = FileUid(who);
    dummyg = FileGid(who);
    perms = FilePerms(who);
    stat(C(who), &st);
    st.st_uid = dummyu;
    st.st_gid = dummyg;
    COnSyscallExit *osce = FinishNormal();
    OnSyscallExitSetBackup2(osce, ptr, &st, sizeof(st));
  } else
    FinishNormal();
}
static void InterceptFstatat() {
  void *ptr = (void *)GetArg(2);
  char who[1024];
  struct stat st;
  COnSyscallExit *osce = AtSytle(who, 0, 1);
  if (!is_empty_path(who)) {
    UnChrootPath(who, who);
    stat(C(who), &st);
    st.st_uid = FileUid(who);
    st.st_gid = FileGid(who);
    OnSyscallExitSetBackup2(osce, ptr, &st, sizeof(st));
  }
}

#undef W

static void FakeGroup() {
  uid_t who = 0;
  pid_t pid = mc_current_pid;
  CProcInfo *pinf = GetProcInfByPid(pid);
  if (pinf) {
    who = pinf->gid;
  }
  FinishPass1(who);
}

static CMountPoint *AddMountPoint(const char *dst, const char *src) {
  char *rp;
  CMountPoint *mp = calloc(1, sizeof *mp);
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
static void FakeUser() {
  uid_t who = 0;
  pid_t pid = mc_current_pid;
  CProcInfo *pinf = GetProcInfByPid(pid);
  if (pinf) {
    who = pinf->gid;
  }
  FinishPass1(who);
}
static COnSyscallExit *AtSytle(char *_to, int64_t fd, int64_t path) {
  char dst[1024], chroot[1024], rel[1024], old[1024];
  char *ptr;
  char to[1024], palidrone[4];
  int have_fd;
  int is_rel = 0;
  ReadPTraceString(dst, ptr = (char *)GetArg(path));
  SetEnding(dst, MC_UNCHROOTED_ENDING);
  if (dst[0] == '/') { // Abolsute
    StrCpyWithEnding(to, C(dst));
  } else {
    strcpy(to, dst);
    is_rel = 1;
    have_fd = GetArg(fd);
  }
  int64_t restore = WritePTraceString(old, ptr, to);
  if (_to && is_rel) {
    if (FdToStr(rel, have_fd)) {
      sprintf(chroot, "%s/%s", rel, to);
      GetEnding(palidrone, rel);
      SetEnding(chroot, palidrone);
      StrCpyWithEnding(_to, C(chroot));
    } else if (_to)
      _to[0] = 0;
  } else if (_to && !is_rel) {
    NormailizePath(_to, to);
  }
  COnSyscallExit *osce = FinishNormal();
  OnSyscallExitSetBackup1(osce, ptr, old, restore);
  return osce;
}

static void InterceptLinkat() {
  char a[1024], b[1024];
  char old[2048];
  char total[2048];
  char *write_to = (char *)GetArg(1);
  int64_t i;
  for (i = 0; i != 2; i++) {
    char dst[1024], rel[1024];
    char *to = i ? b : a;
    char *ptr;
    ReadPTraceString(dst, ptr = (char *)GetArg(1 + 2 * i));
    if (dst[0] == '/') { // Abolsute
      StrCpyWithEnding(to, C(dst));
    } else
      StrCpyWithEnding(to, dst);
  }
  int64_t total_len = 2 + strlen(a) + strlen(b);
  sprintf(total, "%s%c%s", a, 0, b);
  PTraceRead(mc_current_tid, old, write_to, total_len);
  PTraceWriteBytes(write_to, total, total_len);
  SetArg(3, (int64_t)(write_to + 1 + strlen(a)));
  COnSyscallExit *osce = FinishNormal();
  OnSyscallExitSetBackup1(osce, write_to, old, total_len);
}
static COnSyscallExit *InterceptSysctl0(int *_name, int nlen, void *_old,
                                        size_t *_old_sz, void *_new,
                                        size_t _new_sz) {
  int ret = 0;
  if (nlen <= 0) {
  defacto:
    SetSyscall(202);
    SetArg(0, (int64_t)_name);
    SetArg(1, nlen);
    SetArg(2, (int64_t)_old);
    SetArg(3, (int64_t)_old_sz);
    SetArg(4, (int64_t)_new);
    SetArg(5, _new_sz);
    return FinishNormal();
  }
  int *name = calloc(sizeof(int), nlen);
  PTraceRead(mc_current_tid, name, _name, nlen * sizeof(int));
  size_t ret_ln = 0, ptr = 0, dummy;
  size_t max_sz = 0;
  struct kinfo_proc *ret_procs = NULL, *tmp_proc;
  struct kinfo_file *ret_files = NULL, *real_ret_files = NULL;
  CProcInfo *cur = proc_head.next, *head = &proc_head;
  switch (name[0]) {
  case CTL_KERN:
    if (nlen >= 3) {
      if (name[1] == KERN_PROC) {
        if (nlen == 3 &&
            (name[2] == KERN_PROC_ALL || name[2] == KERN_PROC_PROC))
          ; // All is good
        else if (nlen < 4)
          break;
        switch (name[2] & ~KERN_PROC_INC_THREAD) {
        case KERN_PROC_FILEDESC:
          while (cur != head) {
            if (cur->pid == name[3]) {
              ret_ln = 1;
              break;
            }
            cur = cur->next;
          }
          if (!ret_ln) {
            ret = -1;
            goto dump_files;
          }
          if (ret = sysctl(name, 4, NULL, &ret_ln, NULL, 0)) {
            goto dump_files;
          }
          ret_files = calloc(1, ret_ln);
          if (ret = sysctl(name, 4, ret_files, &ret_ln, NULL, 0)) {
            goto dump_files;
          }
          size_t unchrooted_len;
          char path2[1024];
          for (int r = 0; r != 2; r++) {
            unchrooted_len = 0;
            for (ptr = 0; ptr < ret_ln;) {
              struct kinfo_file *ret_file = (char *)ret_files + ptr, *cur;
              dummy = ret_file->kf_structsize -
                      offsetof(struct kinfo_file, kf_path);
              memcpy(path2, ret_file->kf_path, dummy);
              path2[dummy] = 0;

              if (real_ret_files) {
                memcpy(cur = (char *)real_ret_files + unchrooted_len, ret_file,
                       offsetof(struct kinfo_file, kf_path));
                UnChrootPath(cur->kf_path, path2);
              }

              unchrooted_len += sizeof(struct kinfo_file);

              ptr += ret_file->kf_structsize;
            }
            if (!real_ret_files)
              real_ret_files = calloc(1, unchrooted_len);
          }
          ret_ln = unchrooted_len;
        dump_files:
          if (ret) {
            free(ret_files);
            free(real_ret_files);

            return FinishFail(ret);
          } else {
            if (_old) {
              PTraceRead(mc_current_tid, &max_sz, _old_sz, sizeof(size_t));
              PTraceWrite(mc_current_tid, _old, real_ret_files,
                          max_sz > ret_ln ? ret_ln : max_sz);
            }
            if (_old_sz) {
              PTraceWrite(mc_current_tid, _old_sz, &ret_ln, sizeof(size_t));
            }
          }
          free(ret_files);
          free(real_ret_files);
          return FinishPass0();
        case KERN_SECURELVL:
          /* 21 Nroot here,maybe i will implement this in the future
           *
           */
          break;
        case KERN_PROC_PATHNAME:
          while (cur != head) {
            if (cur->pid == name[3]) {
              ret_ln = sizeof(struct kinfo_proc);
              break;
            }
            cur = cur->next;
          }
          if (!ret_ln) {
            ret = -1;
            goto dump_files;
          }
          for (int i = 0; i != 2; i++) {
            if (ret = sysctl(name, nlen, ret_procs, &ret_ln, NULL, 0)) {
              goto dump_procs;
            }
            ret_procs = calloc(1, ret_ln + 1);
          }
          if (ret_procs && name[2] == KERN_PROC_PATHNAME) {
            UnChrootPath((char *)ret_procs, (char *)ret_procs);
            ret_ln = strlen((char *)ret_procs) + 1;
          }
          goto dump_procs;
        case KERN_PROC_PGRP:
#define KERN_PROC_PRED(predicate)                                              \
  for (cur = head->next; cur != head; cur = cur->next) {                       \
    if (predicate) {                                                           \
      ret_ln +=                                                                \
          GetKInfoProc(NULL, cur->pid, !!(name[2] & KERN_PROC_INC_THREAD));    \
    }                                                                          \
  }                                                                            \
  ret_procs = calloc(1, ret_ln);                                               \
  ret_ln = 0;                                                                  \
  for (cur = head->next; cur != head; cur = cur->next) {                       \
    if (predicate)                                                             \
      if (0 < GetKInfoProc(tmp_proc = &((char *)ret_procs)[ret_ln], cur->pid,  \
                           !!(name[2] & KERN_PROC_INC_THREAD)))                \
        ret_ln += tmp_proc->ki_structsize;                                     \
  }                                                                            \
  goto dump_procs;
          KERN_PROC_PRED(getpgid(cur->gid) == name[3]);
          break;
        case KERN_PROC_SESSION:
          KERN_PROC_PRED(getsid(cur->gid) == name[3]);
          break;
        case KERN_PROC_UID:
          KERN_PROC_PRED(cur->euid == name[3]);
          break;
        case KERN_PROC_RUID:
          KERN_PROC_PRED(cur->uid == name[3]);
          break;
        case KERN_PROC_PID:
          KERN_PROC_PRED(cur->pid == name[3]);
          break;
        case KERN_PROC_ALL:
          KERN_PROC_PRED(1);
          break;
        case KERN_PROC_TTY:
          // TODO
          KERN_PROC_PRED(0);
          break;
        case KERN_PROC_GID:
          KERN_PROC_PRED(cur->egid == name[3]);
          break;
        case KERN_PROC_RGID:
          KERN_PROC_PRED(cur->gid == name[3]);
          break;
        case KERN_PROC_PROC:
          /* 21 Nroot
           *  See kern_proc.c in FreeBSD src code
           */
          KERN_PROC_PRED(1);
          break;
        dump_procs:
          if (!ret) {
            if (_old) {
              PTraceRead(mc_current_tid, &max_sz, _old_sz, sizeof(size_t));
              PTraceWrite(mc_current_tid, _old, ret_procs,
                          max_sz > ret_ln ? ret_ln : max_sz);
            }
            if (_old_sz) {
              PTraceWrite(mc_current_tid, _old_sz, &ret_ln, sizeof(size_t));
            }
          }
          SetSyscall(20); // getpid
          free(ret_procs);
          if (ret) {
            return FinishFail(ret);
          } else {
            return FinishPass0();
          }
        }
      }
    }
  }
  free(name);
  goto defacto;
}
static void InterceptSysctlByname() {
  char name[1024];
  size_t len = 100;
  int poodles[100];
  void *write_to = (char *)GetArg(0);
  int *have = NULL, *backup = NULL;
  PTraceRead(mc_current_tid, name, write_to, GetArg(1));
  name[GetArg(1)] = 0;
  if (sysctlnametomib(name, poodles, &len)) {
  fail:;
    if (have)
      free(have);
    if (backup)
      free(backup);
    SetSyscall(20);
    FinishFail(-errno);
    return;
  }
  have = calloc(sizeof(int), len);
  backup = calloc(sizeof(int), len);
  if (sysctlnametomib(name, have, &len))
    goto fail;
  PTraceRead(mc_current_tid, backup, write_to, sizeof(int) * len);
  PTraceWrite(mc_current_tid, write_to, have, sizeof(int) * len);
  SetSyscall(202); // "Normal" sysctl
  COnSyscallExit *osce =
      InterceptSysctl0(write_to, len, (void *)GetArg(2), (void *)GetArg(3),
                       (void *)GetArg(4), GetArg(5));
  OnSyscallExitSetBackup1(osce, write_to, backup, sizeof(int) * len);
  free(backup);
  free(have);
}
static void TheEnd() {
  CProcInfo *cur;
  for (cur = proc_head.next; cur != &proc_head; cur = cur->next) {
    // Kill the procs before they get turnt into ZOMBIES
    kill(cur->pid, SIGKILL);
    ptrace(PT_DETACH, cur->pid, (caddr_t)1, 0);
  }
  HashTableDone();
}
static int Wait(int *status,struct __wrusage *usage, siginfo_t *info) {
again:;
	CProcInfo *pinf=proc_head.next;
			struct ptrace_lwpinfo inf;
			int ofroozen;
	while(pinf!=&proc_head) {
		if(pinf->flags&PIF_DONE_WAITING&&pinf->sc_on_exit) {
			pinf->flags&=~PIF_DONE_WAITING;
			if(status) *status=pinf->saved_status;
			//At syscall enter
			mc_current_pid=pinf->pid;
			mc_current_tid=pinf->sc_on_exit->tid; //TODO whoops
			ofroozen=pinf->flags&PIF_FROZEN;
			ptrace(PT_LWPINFO,mc_current_tid,(caddr_t)&inf,sizeof inf);
			pinf->flags&=~PIF_FROZEN;
			PT_SyscallExit();
			pinf->flags|=ofroozen;
			goto again;
		}
		pinf=pinf->next;
	}
w:;
	pid_t poo=wait6(P_ALL,-1,status,WUNTRACED | WEXITED | WTRAPPED | WSTOPPED |
                               WCONTINUED,usage,info);
                   
    return poo;
}
int main(int argc, const char *argv[], const char **env) {
  signal(SIGHUP, SIG_IGN);
  pid_t pid, pid2;
  int64_t idx;
  int ch;
  char chroot_bin[1024];
  char hflag = 0;
  char tflag = 0;
  char Xflag = 0;
  if (argc < 3) {
  help:;
    const char *me = argc > 0 ? argv[0] : "mrchroot";
    fprintf(stderr,
            "Usage %s [chroot] [shell] ...\n"
            "  %s -t [base.tar] [chroot]\n"
            "	-h	Display this help message\n"
            "	-t	Extract a tar with valid permisons into [chroot]\n"
            "	-X	Enable X11 stuff(see source code)\n",
            me, me);
    return 1;
  }
  while ((ch = getopt(argc, argv, "thX")) != -1) {
    if (ch == 'h') {
      hflag = 1;
    } else if (ch == 'X') {
      Xflag = 1;
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

  chroot_root.next = &chroot_root;
  chroot_root.last = &chroot_root;

  waiters.last = &waiters;
  waiters.next = &waiters;

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
    if (Xflag) {
      AddMountPoint("/var/run", "/var/run");
      // AddMountPoint("/proc", "/proc");
      AddMountPoint("/tmp", "/tmp"); // Needed for /tmp/.X11-ubix/Xx
    }
  }

  if ((pid = fork())) {
    procctl(P_PID, 0, PROC_REAP_ACQUIRE, NULL);
    HashTableInit("./perms.db");
    atexit(&HashTableDone);
    int cond;
    CProcInfo *pinf0 = GetProcInfByPid(pid);
    pinf0->uid = 0;
    pinf0->gid = 0;
    pinf0->euid = 0;
    pinf0->egid = 0;
    pinf0->ngrps = 1;
    pinf0->groups[0] = 0; // Wheel
    pinf0->chrooted_at = ChrootAt("/");
    pinf0->login = strdup("root");
    while ((pid2 = Wait(&cond,
                               &mc_current_usage,&mc_current_siginfo
                           ))) {
      if ((WIFSIGNALED(cond) || WIFEXITED(cond)) && pid2 == pid) {
        struct procctl_reaper_kill rkill = {0};
        rkill.rk_sig = SIGKILL;
        rkill.rk_flags = 0; // Kill all?
        procctl(P_PID, 0, PROC_REAP_KILL, &rkill);
        exit(0);
      }
      struct ptrace_lwpinfo inf;
      CProcInfo *pinf = GetProcInfByPid(pid2);
      pinf->saved_status=cond;
      ptrace(PT_LWPINFO, pid2, (caddr_t)&inf, sizeof inf);

      /* 21 Nroot here,I have mc_current_pid/mc_current_tid
       *   ALWAYS USE mc_current_tid(LWP) instead of the pid because
       *   FreeBSD will choose a random thread of a pid
       */
      mc_current_pid = pid2;
      mc_current_tid = inf.pl_lwpid;
      mc_current_wait_cond=cond;
      // Nested ptrace,delegate poo poo sauce to the "simulated" ptrace if
      // we are being debugged;
      {
        CProcInfo *pinf2;
        if (pinf->debugged_by) {
          pid_t to = pinf->debugged_by;
          if (!to)
            to = pinf->parent;
          int antipode=~0;
          int esce=(pinf->flags&PIF_TO_SCE)?1:0;
		  int escx=(pinf->flags&PIF_TO_SCX)?1:0;
	      if(!esce&&!(pinf->flags&PIF_SYSCALL))
			antipode&=~PL_FLAG_SCE;
          if(!escx&&!(pinf->flags&PIF_SYSCALL))
			antipode&=~PL_FLAG_SCX;
          if ((pinf->ptrace_event_mask & inf.pl_flags&antipode)) {
          send_out:;
            kill(to,SIGCHLD);
            DelegatePtraceEvent(pid2, cond,&mc_current_usage,&mc_current_siginfo);
            // Heres the DEAL.PT_TRACE_ME sets the PTRACE_EXEC flag in the
            // ptrace state(not reset when used)
            continue;
          }
        }
      }
    normal:;
    if (WIFEXITED(cond)) {
        kill	(pinf->parent, SIGCHLD);
        DelegatePtraceEvent(pid2, cond,&mc_current_usage,&mc_current_siginfo);
        pid_t par = pinf->parent;
        pinf->flags |= PIF_EXITED;
        RemoveProc(pid2);
        continue;
      } else if (WIFSIGNALED(cond)) {
        if (1) {
          puts("l2");
          DelegatePtraceEvent(pid2, cond,&mc_current_usage,&mc_current_siginfo);
          if (pinf->debugged_by) {
          } else {
            ptrace(PT_CONTINUE, pid2, (void *)1, WTERMSIG(cond));
            RemoveProc(pid2);
          }
          continue;
        }
      }
      
      if (inf.pl_flags & PL_FLAG_SCX) {
        COnSyscallExit **write_to = &pinf->sc_on_exit, *have = pinf->sc_on_exit;
        while (have) {
          if (inf.pl_lwpid == have->tid) {
            *write_to = have->next;
            if (have->restore1) {
              PTraceWriteBytes(have->restore_ptr1, have->restore1,
                               have->restore_len1);
              free(have->restore1);
            }
            if (have->restore2) {
              if (have->restore_len2 == sizeof(struct stat)) {
                struct stat *st = have->restore2;
              }
              PTraceWriteBytes(have->restore_ptr2, have->restore2,
                               have->restore_len2);
              free(have->restore2);
            }
            if (have->restore3) {
              if (have->restore_len3 == sizeof(struct stat)) {
                struct stat *st = have->restore3;
              }
              PTraceWriteBytes(have->restore_ptr3, have->restore3,
                               have->restore_len3);
              free(have->restore3);
            }
            if (!have->normal)
              SetReturn(have->ret_code, have->error);

            COnSyscallExit *have2 = have->next;
            if (have->on_exit_cb)
              have->on_exit_cb(have);
            bool no_cont = have->no_continue;
            free(have);
            if (no_cont) // Dont continue the syscall
              goto next;
            goto defacto;
          }
          write_to = &have->next;
          have = have->next;
        }
      }
      if (inf.pl_flags & PL_FLAG_EXITED) {
        // DelegatePtraceEvent
        goto syscall;
      }
      if (inf.pl_flags & PL_FLAG_EXITED) {
        pinf->flags |= PIF_EXITED;
        continue;
      }
      if (inf.pl_flags & (PL_FLAG_BORN | PL_FLAG_EXEC)) {
        pinf->flags &= ~PIF_EXITED;
        ptrace(PT_FOLLOW_FORK, mc_current_tid, NULL, 1);
        ptrace(PT_LWP_EVENTS, mc_current_tid, NULL, 1);
        goto syscall;
      } else if (inf.pl_flags &
                 (PL_FLAG_FORKED | PL_FLAG_VFORKED | PL_FLAG_VFORK_DONE)) {
        ptrace(PT_FOLLOW_FORK, mc_current_tid, NULL, 1);
        ptrace(PT_LWP_EVENTS, mc_current_tid, NULL, 1);
        // Inheret our hacks from LD_PRELOAD hack
        CProcInfo *parent = pinf;
        CProcInfo *child = GetProcInfByPid(inf.pl_child_pid);
        child->uid = parent->uid;
        child->gid = parent->gid;
        child->euid = parent->euid;
        child->egid = parent->egid;
        child->suid = parent->suid;
        child->sgid = parent->sgid;
        child->chrooted_at = parent->chrooted_at;
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
        goto syscall;
      } else if (inf.pl_flags & PL_FLAG_CHILD) {
        ptrace(PT_FOLLOW_FORK, mc_current_tid, NULL, 1);
        ptrace(PT_LWP_EVENTS, mc_current_tid, (void *)1, 0);
        goto syscall;
      } else if (inf.pl_flags & PL_FLAG_SCE) {
        // fprintf(stderr,"%d,%d\n",pid2,inf.pl_syscall_code);
        switch (inf.pl_syscall_code) {

        case MR_CHROOT_NOSYS: {
          char chrooted[1024];
          // In preload_hack.c,I use an indrtiect syscall,so use argument 1
          // instead of 0
          pinf->hacks_array_ptr = (CMrChrootHackPtrs *)GetArg(1);

          char *write_chroot_to = (char *)GetArg(2);
          StrCpyWithEnding(chrooted, C("/" MC_UNCHROOTED_ENDING));
          PTraceWriteBytes(write_chroot_to, chrooted, strlen(chrooted) + 1);
          SetSyscall(36); // Sync Takes no arguments,repalce with valid
          // syscall(to avoid a signal for invalid syscall)
          FinishNormal();
        } break;
        case 0: // syscall
          goto defacto;
        case 1: // exit
          goto defacto;
        case 2: // fork
          goto defacto;
        case 3: // read
          goto defacto;
        case 4: // write
          goto defacto;
        case 5: { // open
          int af = 0;
          int64_t want_ = GetArg(1);
          if (want_ & O_RDONLY)
            af |= R_OK;
          if (want_ & O_RDWR)
            af |= R_OK | W_OK;
          if (want_ & O_EXEC)
            af |= X_OK;
#define PERMCHECK(af, PATH)                                                    \
  {                                                                            \
    char dst[1024];                                                            \
    ReadPTraceString(dst, (char *)GetArg(PATH));                               \
    SetEnding(dst, MC_UNCHROOTED_ENDING);                                      \
    if (0 != HasPerms((af), dst)) {                                            \
      SetSyscall(20); /*  Doesnt do anything*/                                 \
      FinishFail(HasPerms((af), dst));                                         \
      break;                                                                   \
    }                                                                          \
  }
          InterceptOpen();
        } break;
        case 6: { // close
          CProcInfo *pinf = GetProcInfByPid(pid2);
          FDCacheRem(pinf->fd_cache, GetArg(0));
          FinishNormal();
          break;
        }
        case 7: { // wait4
          pid_t want = GetArg(0);
          int f = GetArg(2);
          InterceptWait(0,want, (int *)GetArg(1), f,NULL,NULL);
          continue;
          break;
        }
        case 532: { // wait6
          pid_t want = GetArg(1);
          SetArg(1, -1); // Wait for self(we will interupt later)
          InterceptWait(6,want, (int *)GetArg(2), GetArg(3),(void*)GetArg(4),(void*)GetArg(5));
          continue;
          break;
        }
        case 9: // link
          PERMCHECK(W_OK, 1);
          InterceptLink();
          break;
        case 10: // unlink
          PERMCHECK(W_OK, 0);
          InterceptUnlink();
          break;
        case 12: { // chdir
          PERMCHECK(X_OK | F_OK, 0);
          InterceptChdir();
          break;
        }
        case 13: // fchdir
#define FPERMCHECK(af, PATH)                                                   \
  {                                                                            \
    char dst[1024];                                                            \
    if (FdToStr(dst, GetArg((int64_t)PATH)))                                   \
      if (0 != HasPerms((af), dst)) {                                          \
        SetSyscall(20); /*  Doesnt do anything*/                               \
        FinishFail(HasPerms((af), dst));                                       \
        break;                                                                 \
      }                                                                        \
  }
          FPERMCHECK(X_OK | F_OK, 0);
          FakeSuccess();
          break;
        case 20: // getpid
          goto defacto;
        case 21: // mount
          InterceptMount();
          break;
        case 22: // unmount
          InterceptUnmount();
          break;
        case 26: // ptrace
          InterceptPtrace();
          break;
        case 30: // accept
        {
          FinishNormal();
        } break;
        case 33: // access
          PERMCHECK(R_OK, 0);
          InterceptAccess();
          break;
        case 34: { // chflags
          /*
           * 21 Nrootconauto ,ill have to emulate
           * SF_APPEND,SF_NOUNLINK,SF_IMMUATABLE
           * */
          PERMCHECK(W_OK | F_OK, 0);
          INTERCEPT_FILE1(0);
        } break;
        case 35: { // fchflags
          /*
           * Look at 34:
           * */
          FPERMCHECK(W_OK | F_OK, 0);
          FinishNormal();
        }
        break;
        case 37: { // kill
          /* 21 Nrootcomauto here,Ask nrootconauto to implement(and) killing
           *other procs (TODO handle p<=0)
           **/
          CProcInfo *me = GetProcInfByPid(pid2);
          pid_t want = GetArg(0);
          int poo = GetArg(1);
          int passed = 0;
          if (want > 0) {
            CProcInfo *cur;
            SetSyscall(20); // Dont do anyhthjing(getpid)
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
                    (cur->uid == me->uid ||
                     cur->euid == me->uid) || // cur->real
                    (cur->uid == me->euid ||
                     cur->euid == me->euid) || // cur->euid
                    (poo == SIGCONT && (getsid(want) == getsid(pid2)))) {
                  int e = kill(want, poo);
                  passed = 1;
                  if (e)
                    FinishFail(e);
                  else {
                    FinishPass0();
                  }
                  break;
                } else {
                  // Not permiteed 2 kill
                  FinishFail(-EPERM);
                  break;
                }
              }
            }
            if (!passed)
              FinishFail(-ESRCH);
          }
        } break;
        case 39: // getppid TODO
          goto defacto;
        case 41: { // dup
          int64_t who = GetArg(0);
          COnSyscallExit *osce = FinishNormal();
          osce->on_exit_cb = &DupFD;
          osce->user_data = who;
        } break;
        case 43: { // getegid
          // TODO wut is an egid
          CProcInfo *inf = GetProcInfByPid(pid2);
          FinishPass1(inf->egid);
        } break;
        case 47: { // getgid
          CProcInfo *inf = GetProcInfByPid(pid2);
          FinishPass1(inf->gid);
        } break;
        case 49: { // getlogin
          CProcInfo *pinf = GetProcInfByPid(pid2);
          // int64_t len = GetArg(pid2, 1);
          char *to = (char *)GetArg(0);
          size_t len = GetArg(1);
          const char *name = "???";
          if (pinf->login) {
            name = pinf->login;
          }
          if (to && len >= 1 + strlen(name)) {
            COnSyscallExit *osce = FinishPass0();
            OnSyscallExitSetBackup1(osce, to, name, strlen(name) + 1);
          } else {
            FinishFail(-ERANGE);
          }
        } break;
        case 50: // setlogin
        {
          char ln[MAXLOGNAME];
          CProcInfo *pinf = GetProcInfByPid(pid2);
          if (ReadPTraceString(ln, (char *)GetArg(0))) {
            if (pinf->login)
              free(pinf->login);
            pinf->login = strdup(ln);
          }
          FinishPass0();
        }
        case 54: // ioctl
          goto defacto;
        case 56: { // revoke
          PERMCHECK(W_OK | F_OK, 0);
          INTERCEPT_FILE1(0);
        } break;
        case 57: { // symlink
          PERMCHECK(W_OK, 0);
          CProcInfo *inf = GetProcInfByPid(pid2);
          char name[1024];
          ReadPTraceString(name, (char *)GetArg(0));
          SetEnding(name, MC_UNCHROOTED_ENDING);
          {
            INTERCEPT_FILE1(1);
          }
          ChrootDftOwnership(name);
        } break;
        case 58: // readlink
          InterceptReadlink();
          break;
        case 59: { // execve
          PERMCHECK(X_OK | F_OK, 0);
          InterceptExecve();
          goto next;
        } break;
        case 61: { // chroot TODO
          CProcInfo *pinf = GetProcInfByPid(pid2);
          SetSyscall(20);
          if (pinf->uid == 0 || pinf->euid == 0) {
            char pushinp[2048];
            GetProcCwd(pushinp);
            strcat(pushinp, "/");
            ReadPTraceString(pushinp + strlen(pushinp), (char *)GetArg(0));
            NormailizePath(pushinp, pushinp);
            pinf->chrooted_at = ChrootAt(pushinp);
            FinishPass0();
          } else
            FinishFail(-EPERM);
          break;
        }
        case 66: // vfork
          goto defacto;
        case 73: // munmap
          goto defacto;
        case 74: // mprotect
          goto defacto;
        case 79: // getgroups
        {
          CProcInfo *pinf = GetProcInfByPid(pid2);
          long cnt = GetArg(0);
          if (cnt < pinf->ngrps) {
            if (cnt > 0)
              PTraceWrite(mc_current_tid, (void *)GetArg(1), pinf->groups,
                          cnt * sizeof(gid_t));
            FinishFail(-EINVAL);
          } else {
            PTraceWrite(mc_current_tid, (void *)GetArg(1), pinf->groups,
                        pinf->ngrps * sizeof(gid_t));
            FinishPass1(pinf->ngrps);
          }
        } break;
        case 80: { // setgroups
          CProcInfo *pinf = GetProcInfByPid(pid2);
          if (pinf->uid == 0 || pinf->euid == 0) {
            long cnt = GetArg(0);
            pinf->ngrps = cnt;
            PTraceRead(mc_current_tid, pinf->groups, (void *)GetArg(1),
                       cnt * sizeof(gid_t));
            FinishPass0();
          } else {
            FinishNormal();
            // Failure
          }
        } break;
        case 81: // getpgrp TODO
                 // Ask a kevalin
          goto defacto;
        case 82: // setpgid TODO
                 // You'll need to do some digging
          goto defacto;
        case 83: // setitimer
          goto defacto;
        case 85: // swapon
          // no way
          goto defacto;
        case 90: // dup2
        {
          uint64_t who = GetArg(0) | (GetArg(1) << 32);
          COnSyscallExit *osce = FinishNormal();
          osce->on_exit_cb = &DupFD2;
          osce->user_data = who;
        } break;
        case 92: // fcntl
                 // NOT NOW
                 // TODO
          goto defacto;
        case 93: // select
          goto defacto;
        case 15: // chmod
          PERMCHECK(W_OK, 0);
          InterceptChmod();
          break;
        case 16: // chown
          PERMCHECK(W_OK, 0);
          InterceptChown();
          break;
        case 23: // setuid 21
          InterceptSetuid();
          break;
        case 24: // getuid
          InterceptGetuid();
          break;
        case 25: // geteuid
          InterceptGeteuid();
          break;
        case 124: { // fchmod
          char have[1024];
          FPERMCHECK(F_OK | W_OK, 0);
          if (FdToStr(have, GetArg(0)))
            HashTableSet(have, FileUid(have), FileGid(have), GetArg(1));
          FakeSuccess();
          break;
        }
        case 122: { // settimeofday
          /*
           * Ask nroot,he will add it. I dont think anyone will notice for now
           */
          goto defacto;
        }
        case 123: { // fchown
          FPERMCHECK(F_OK | W_OK, 0);
          char who[1024];
          CProcInfo *pinf = GetProcInfByPid(pid2);
          if (FdToStr(who, GetArg(0))) {
            HashTableSet(who, GetArg(1), GetArg(2), FilePerms(who));
          }
          FinishPass0();
          break;
        }
        case 127: { // setregid
                    /*
                     * 21 Nroot here,im just copy-paste-swaping code from 126(segreuid)
                     * Normal users may only swp ugid<->egid
                     */
          CProcInfo *inf = GetProcInfByPid(pid2);
          gid_t wantu = GetArg(0);
          gid_t wante = GetArg(1);

          if ((inf->gid == 0 || inf->egid == 0) ||      // Superuser 21
              (inf->gid == wante && inf->egid == wantu) // swap gid<->egid
          ) {
            inf->gid = wantu;
            inf->egid = wante;
            FakeSuccess();
          } else if (wante == -1 || wantu == -1) {
            if (wante == inf->gid) {
              inf->egid = wante;
            }
            if (wantu == inf->egid) {
              inf->gid = wantu;
            }
            FakeSuccess();
          } else {
            FinishFail(-EPERM);
          }
          break;
        }

        case 126: { // setreuid
                    /*
                     * 21 Nroot.
                     * Normal users may only swp uid<->euid
                     */
          CProcInfo *inf = GetProcInfByPid(pid2);
          uid_t wantu = GetArg(0);
          uid_t wante = GetArg(1);

          if ((inf->uid == 0 || inf->euid == 0) ||      // Superuser 21
              (inf->uid == wante && inf->euid == wantu) // swap uid<->euid
          ) {
            inf->uid = wantu;
            inf->euid = wante;
            FakeSuccess();
          } else if (wante == -1 || wantu == -1) {
            if (wante == inf->uid) {
              inf->euid = wante;
            }
            if (wantu == inf->euid) {
              inf->uid = wantu;
            }
            FakeSuccess();
          } else {
            FinishFail(-EPERM);
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
          ReadPTraceString(dst, (char *)GetArg(1));
          ReadPTraceString(chr, (char *)GetArg(0));
          SetEnding(dst, MC_UNCHROOTED_ENDING);
          SetEnding(chr, MC_UNCHROOTED_ENDING);
          ChrootedRealpath(chr, chr);
          uid_t u = FileUid(chr);
          gid_t g = FileGid(chr);
          uint32_t p = FilePerms(chr);
          INTERCEPT_FILE2(0, 1);
          ChrootedRealpath(chr2, dst);
          /* 21 Nroot here,renamin' keeps perms ok
           */
          HashTableRemove(chr);
          HashTableSet(chr2, u, g, p);
        } break;
        case 131: // flock
        {
          goto defacto;
        }
        case 132: { // mkfifo
          char dst[1024], failed;
          PERMCHECK(W_OK, 0);
          CProcInfo *inf = GetProcInfByPid(pid2);
          ReadPTraceString(dst, (char *)GetArg(0));
          SetEnding(dst, MC_UNCHROOTED_ENDING);
          INTERCEPT_FILE1(0);
          ChrootDftOwnership(dst);
        } break;
        case 136: { // mkdir
          char dst[1024], fail;
          PERMCHECK(W_OK, 0);
          CProcInfo *inf = GetProcInfByPid(pid2);
          ReadPTraceString(dst, (char *)GetArg(0));
          SetEnding(dst, MC_UNCHROOTED_ENDING);
          {
            INTERCEPT_FILE1(0);
          }
          ChrootDftOwnership(dst);
        } break;
        case 137: { // rmdir
          PERMCHECK(W_OK | F_OK, 0);
          INTERCEPT_FILE1(0);
          break;
        }
        case 138: { // utimes
          PERMCHECK(W_OK | F_OK, 0);
          INTERCEPT_FILE1(0);
        } break;
        case 147: // setsid TODO?
          goto defacto;
        case 148: { // qoutactl
          INTERCEPT_FILE1(0);
        } break;
        case 161 ... 162: { // lgetfh
                            /* 21 Nrootconauto here,
                             *   What permisions does it need?
                             */
          INTERCEPT_FILE1(0);
        } break;
        case 165: // sysarch
          goto defacto;
        case 181: { // setgid
        setgid:;
          /* 21 Nroot here
           * Basically we need be (of effectively) be root or have SSSame
           *gid/egid
           **/
          CProcInfo *inf = GetProcInfByPid(pid2);
          uid_t want = GetArg(0);
          if ((!inf->euid || !inf->uid) ||               // Super user
              (inf->gid == want || inf->egid == want)) { // uid or euid 21
            inf->sgid = inf->egid = inf->gid = want;
            FinishPass0();
          } else {
            FinishFail(-EPERM);
          }
        } break;
        case 182: // setegid
        {
          CProcInfo *inf = GetProcInfByPid(pid2);
          uid_t want = GetArg(0);
          if ((!inf->euid || !inf->uid) ||               // Super user
              (inf->gid == want || inf->egid == want)) { // uid or euid 21
            inf->egid = want;
            FinishPass0();
          } else {
            FinishFail(-EPERM);
          }
        } break;
        case 183: // seteuid
        {
          CProcInfo *inf = GetProcInfByPid(pid2);
          uid_t want = GetArg(0);
          if ((!inf->euid || !inf->uid) ||               // Super user
              (inf->uid == want || inf->euid == want)) { // uid or euid 21
            inf->euid = want;
            FinishPass0();
          } else {
            FinishFail(-EPERM);
          }
        } break;
        case 188:
          puts("MrChrootBSD doesnt want FreeBSD11 calls");
          FinishFail(-ENOSYS); // No FreeBSD 11 im sorry
          break;
        case 189:
          puts("MrChrootBSD doesnt want FreeBSD11 calls");
          FinishFail(-ENOSYS); // No FreeBSD 11 im sorry
          break;
        case 190:
          puts("MrChrootBSD doesnt want FreeBSD11 calls");
          FinishFail(-ENOSYS); // No FreeBSD 11 im sorry
          break;
        case 191: { // pathconf
          PERMCHECK(F_OK | R_OK, 0);
          INTERCEPT_FILE1(0);
        } break;
        case 192: { // lpathconf
          PERMCHECK(F_OK | R_OK, 0);
          INTERCEPT_FILE1(0);
        } break;

        case 195: // setrlimit
        {
          ABISetSyscall(mc_current_tid, 20); // getpid
          FinishPass0();
        } break;
        case 198: { // 64bit syscall
          break;
        }
        case 202: { // sysctl
          /* 21 Nroot here,ask him to add sysctls
           *  Keep in mind this is basically a poor man's hypervisor which runs
           * in userspace
           */
          InterceptSysctl0((int *)GetArg(0), (int64_t)GetArg(1),
                           (void *)GetArg(2), (void *)GetArg(3),
                           (void *)GetArg(4), GetArg(5));
          break;
        }
        case 204: { // undelete
          INTERCEPT_FILE1(0);
        } break;
        case 206: {
          FPERMCHECK(W_OK, 0);
          FinishNormal();
          break;
        }
        case 207: // getpgid
          break;
        case 253: // issetugid
                  /* 21 Nrootconauto
                   * Im  not taitned,lets just leave it at that
                   */
          FakeSuccess();
          break;
        case 254: { // lchown
          PERMCHECK(W_OK, 0);
          InterceptChown();
        } break;
        case 274: { // luchmod
          PERMCHECK(W_OK | F_OK, 0);
          InterceptChmod();
        } break;
        case 276: { // lutimes
          PERMCHECK(W_OK | F_OK, 0);
          INTERCEPT_FILE1(0);
        } break;
        case 326: // getcwd
          Intercept__Getcwd();
          break;
        case 338: // jail
          /* 21 Nroot
           *   Stay tuned.
           */
          goto defacto;
        case 340: // sigprocmask
          goto defacto;
        case 311: { // setresuid
          uid_t u = GetArg(0);
          uid_t e = GetArg(1);
          uid_t s = GetArg(2);
          CProcInfo *pinf = GetProcInfByPid(pid2);
          if (pinf->uid == 0 || pinf->euid == 0) {
            if (s != -1)
              pinf->suid = s;
            if (e != -1)
              pinf->euid = e;
            if (u != -1)
              pinf->uid = u;
            SetSyscall(20);
            FakeSuccess();
          }
          break;
        }
        case 312: { // setresgid
          CProcInfo *pinf = GetProcInfByPid(pid2);
          if (pinf->uid == 0 || pinf->euid == 0) {
            uid_t u = GetArg(0);
            uid_t e = GetArg(1);
            uid_t s = GetArg(2);
            SetSyscall(20);
            if (s != -1)
              pinf->sgid = s;
            if (u != -1)
              pinf->gid = u;
            if (e != -1)
              pinf->egid = e;
            SetSyscall(20);
            FakeSuccess();
          } else {
            FinishFail(-EPERM);
          }
          break;
        }
        case 360: { // getresuid
          CProcInfo *pinf = GetProcInfByPid(pid2);
          uid_t *up = (uid_t *)GetArg(0);
          uid_t *ep = (uid_t *)GetArg(1);
          uid_t *sp = (uid_t *)GetArg(2);
          PTraceWrite(mc_current_tid, up, &pinf->uid, sizeof(uid_t));
          PTraceWrite(mc_current_tid, ep, &pinf->euid, sizeof(uid_t));
          PTraceWrite(mc_current_tid, sp, &pinf->suid, sizeof(uid_t));
          SetSyscall(20);
          FakeSuccess();
          break;
        }
        case 361: { // getresgid
          CProcInfo *pinf = GetProcInfByPid(pid2);
          gid_t *up = (gid_t *)GetArg(0);
          gid_t *ep = (gid_t *)GetArg(1);
          gid_t *sp = (gid_t *)GetArg(2);
          PTraceWrite(mc_current_tid, up, &pinf->gid, sizeof(gid_t));
          PTraceWrite(mc_current_tid, ep, &pinf->egid, sizeof(gid_t));
          PTraceWrite(mc_current_tid, sp, &pinf->sgid, sizeof(gid_t));
          SetSyscall(20);
          FakeSuccess();
          break;
        }
        //__acl_xxxx_file
        case 347:
        case 348:
        case 351:
        case 353: {
          INTERCEPT_FILE1(0);
        } break;
        case 356 ... 358: { //	extattr_set_file	extattr_get_file
                            // extattr_delete_file
          INTERCEPT_FILE1(0);
        }
        case 376: { // eaccess
          PERMCHECK(R_OK, 0);
          InterceptAccess();
        } break;
        case 378: // nmount
          InterceptNmount();
          break;
        case 387:
        case 389: { //__mac_get_file/__mac_set_file
          INTERCEPT_FILE1(0);
        } break;
        case 391: { // lchflags
          PERMCHECK(W_OK | F_OK, 0);
          INTERCEPT_FILE1(0);
        } break;
        case 409:
        case 411: { // mac_get_link/set_link
          INTERCEPT_FILE1(0);
        } break;
        case 425: //__acl_get_lni
          PERMCHECK(R_OK, 0);
          {
            INTERCEPT_FILE1(0);
          }
          break;
        case 426: //__acl_set_link
          PERMCHECK(W_OK, 0);
          {
            INTERCEPT_FILE1(0);
          }
          break;
        case 427: //__acl_delte_link
          PERMCHECK(W_OK, 0);
          {
            INTERCEPT_FILE1(0);
          }
          break;
        case 438:
        case 439:
        case 450:;
        case 412 ... 414: { // extattr_set_link/get_link/delete_link
          INTERCEPT_FILE1(0);
        } break;
        case 416: // sigaction
          goto defacto;
        case 417: // sigreturn
          goto defacto;
        case 436: // jail_attach
          goto defacto;
        case 475: // pread
          goto defacto;
        case 476: // pwrite
          goto defacto;
        case 477: { // mmap
        } goto defacto;
        case 479: // truncate
          PERMCHECK(W_OK | F_OK, 0);
          InterceptAccessTruncate();
          break;
        case 480: // ltruncate
          PERMCHECK(W_OK | F_OK, 0);
          InterceptAccessTruncate();
          break;

        case 483: // shm_unlink
          PERMCHECK(W_OK | F_OK, 0);
          InterceptAccessShmUnlink();
          break;
        case 489: { // faccessat
#define FATPERMCHECK(write_to, af, FD, PATH)                                   \
  {                                                                            \
    char dst[1024], full[1024], palidrome[4];                                  \
    ReadPTraceString(dst, (char *)GetArg(PATH));                               \
    SetEnding(dst, MC_UNCHROOTED_ENDING);                                      \
    if (dst[0] == '/') {                                                       \
      StrCpyWithEnding(full, dst);                                             \
    } else {                                                                   \
      if (FdToStr(full, GetArg(FD))) {                                         \
        GetEnding(palidrome, full);                                            \
        strcat(full, "/");                                                     \
        strcat(full, dst);                                                     \
        SetEnding(full, palidrome);                                            \
      }                                                                        \
    }                                                                          \
    if (write_to) {                                                            \
      StrCpyWithEnding((write_to), U(full));                                   \
    }                                                                          \
    if (full[0])                                                               \
      if (0 != HasPerms((af), full)) {                                         \
        SetSyscall(20); /*  Doesnt do anything*/                               \
        FinishFail(HasPerms((af), dst));                                       \
        break;                                                                 \
      }                                                                        \
  }
          FATPERMCHECK(NULL, W_OK | F_OK, 0, 1);
          char dst[1024];
          AtSytle(dst, 0, 1);
          break;
        }

        case 490: // fchmodat
        {
          char use[1024];
          FATPERMCHECK(use, W_OK | F_OK, 0, 1);
          if (!is_empty_path(use))
            HashTableSet(use, FileUid(use), FileGid(use), GetArg(2));
          AtSytle(NULL, 0, 1);
          break;
        }
        case 491: { // fchownat
          char use[1024], failed;
          FATPERMCHECK(use, W_OK | F_OK, 0, 1);
          CProcInfo *inf = GetProcInfByPid(pid2);
          if (is_empty_path(use))
            HashTableSet(use, GetArg(2), GetArg(3), FilePerms(use));
          COnSyscallExit *e = AtSytle(use, 0, 1);
          e->normal = 0;
          // TODO async
          break;
        }
        case 492: // fexecve 21
          /* 21 Nrootconauto
           *  Ask him to do this
           */
          AtSytle(NULL, 0, 1);
          break;
        case 494: // futimesat
          FATPERMCHECK(NULL, W_OK | F_OK, 0, 1);
          AtSytle(NULL, 0, 1);
          break;
        case 495: // linkat
          FATPERMCHECK(NULL, R_OK | F_OK, 0, 1);
          FATPERMCHECK(NULL, W_OK, 2, 3);
          InterceptLinkat();
          break;
        case 496: { // mkdirat
          char dst[1024];
          FATPERMCHECK(NULL, W_OK, 0, 1);
          AtSytle(dst, 0, 1);
          CProcInfo *inf = GetProcInfByPid(pid2);
          HashTableSet(dst, inf->uid, inf->gid, 0755);
        } break;
        case 497: { // mkfifoat
          FATPERMCHECK(NULL, W_OK, 0, 1);
          char dst[1024];
          AtSytle(dst, 0, 1);
          CProcInfo *inf = GetProcInfByPid(pid2);
          if (!is_empty_path(dst)) {
            UnChrootPath(dst, dst);
            HashTableSet(dst, inf->uid, inf->gid, 0644);
          }
        } break;
        case 499: { // openat
          char dst[1024], failed;
          AtSytle(dst, 0, 1);
          // TODO async
        } break;
        case 500: { // readllnkat
          FATPERMCHECK(NULL, R_OK | F_OK, 0, 1);
          char dst[1024];
          char *b = (char *)GetArg(2);
          int64_t l = GetArg(3);
          AtSytle(dst, 0, 1);
        } break;
        case 501: { // renameat
          char tweenty[1024];
          char one[1024], failed;
          FATPERMCHECK(tweenty, W_OK, 2, 3);
          FATPERMCHECK(one, R_OK, 0, 1);
          if (!is_empty_path(tweenty) && !is_empty_path(one)) {
            uid_t u = FileUid(one);
            gid_t g = FileGid(one);
            uint32_t p = FilePerms(one);
            InterceptLinkat(); // CLose enough
            /* 21 Nroot here,renamin' keeps perms ok
             */
            HashTableRemove(one);
            HashTableSet(tweenty, u, g, p);
          }
        } break;
        case 502: { // symlinkat
          char dst[1024];
          FATPERMCHECK(NULL, W_OK, 0, 1);
          AtSytle(dst, 1, 2);
          break;
        }
        case 503: // unlnikat
        {
          char del[1024];
          FATPERMCHECK(NULL, W_OK | F_OK, 0, 1);
          AtSytle(del, 0, 1);
          if (is_empty_path(del)) {
            UnChrootPath(del, del);
            HashTableRemove(del);
          }
        } break;
        case 506 ... 508: // jail stuff TODO
          break;
        case 513: // lpathcnf
          FPERMCHECK(R_OK, NULL)
          INTERCEPT_FILE1(0);
          break;
        case 523: // getloginclass
          // TODO
          FakeSuccess();
          break;
        case 524: // setloginclass
          FakeSuccess();
          break;
        case 98:    // connect
        case 104: { // bind
          char c[1024], bu[1024];
          void *want = (void *)GetArg(1);
          size_t gyatt = GetArg(2);
          struct sockaddr_un *sa_un;
          if (want) {
            sa_un = calloc(1, gyatt + 4);
            PTraceRead(mc_current_tid, sa_un, want, gyatt);
            SetEnding(sa_un->sun_path, MC_UNCHROOTED_ENDING);
            if (sa_un->sun_family == AF_LOCAL) {
              StrCpyWithEnding(c, C(sa_un->sun_path));
              free(sa_un);
              gyatt = offsetof(struct sockaddr_un, sun_path) + strlen(c) + 1;
              sa_un = calloc(1, gyatt);
              sa_un->sun_len = gyatt;
              sa_un->sun_family = AF_LOCAL;
              strcpy(sa_un->sun_path, c);
              PTraceRead(mc_current_tid, bu, want, gyatt);
              PTraceWriteBytes(want, sa_un, gyatt);
              SetArg(2, gyatt);
              COnSyscallExit *osce = FinishNormal();
              OnSyscallExitSetBackup1(osce, want, bu, gyatt);
              free(sa_un);
              break;
            }
            free(sa_un);
          }
          break;
        }
        case 539:   // connectat
        case 538: { // bindat
          char c[1024], bu[1024], fdp[1024];
          void *want = (void *)GetArg(2);
          size_t gyatt = GetArg(3);
          struct sockaddr_un *sa_un;
          if (want) {
            sa_un = calloc(1, gyatt + 4);
            PTraceRead(mc_current_tid, sa_un, want, gyatt);
            SetEnding(sa_un->sun_path, MC_UNCHROOTED_ENDING);
            if (sa_un->sun_family == AF_LOCAL) {
              StrCpyWithEnding(c, sa_un->sun_path);
              free(sa_un);
              if (c[0] == '/') {
              } else {
                FdToStr(fdp, GetArg(0));
                sprintf(c, "%s/%s", fdp, c);
                SetEnding(c, MC_UNCHROOTED_ENDING);
              }
              StrCpyWithEnding(c, C(c));
              gyatt = offsetof(struct sockaddr_un, sun_path) + strlen(c) + 1;
              sa_un = calloc(1, gyatt);
              sa_un->sun_len = gyatt;
              sa_un->sun_family = AF_LOCAL;
              strcpy(sa_un->sun_path, c);
              PTraceRead(mc_current_tid, bu, want, gyatt);
              PTraceWriteBytes(want, sa_un, gyatt);
              SetArg(3, gyatt);
            }
            FinishNormal(); //???
            free(sa_un);
          }
          break;
        }
        case 544: { // procctl
          goto defacto;
        }
        case 546: // futimes
          FPERMCHECK(W_OK, 0);
          FinishPass0();
          break;
        case 547: // utimenat
          FATPERMCHECK(NULL, W_OK | F_OK, 0, 1);
          AtSytle(NULL, 0, 1);
          break;
        case 551: // fstat
                  // FPERMCHECK(R_OK|F_OK,0);
          InterceptFstat();
          break;
        case 552: { // fstatat
                    // FATPERMCHECK(NULL,R_OK|F_OK,0,1);
          InterceptFstatat();
        } break;
        case 553:
          goto defacto;
        case 554: // getdirentries
          // Filename is from fd
          goto defacto;
        case 540: // chflagsat
          FATPERMCHECK(NULL, W_OK | F_OK, 0, 1);
          AtSytle(NULL, 0, 1);
          break;
        case 556: // fstatfs
          goto defacto;
        case 559: { // mknodat
                    // Only super uses can make nodes
                    // AtSytle(NULL, pid2, 0, 1);
        } goto defacto;
        case 563: // getrandom
          goto defacto;

        case 564: { // getfhat
          FATPERMCHECK(NULL, R_OK | F_OK, 0, 1);
          AtSytle(NULL, 0, 1);
        } break;
        case 565: { // fhlink
          FPERMCHECK(W_OK, 1);
          INTERCEPT_FILE1(1);
        } break;
        case 566: { // fhlinkat
          FATPERMCHECK(NULL, W_OK, 1, 2);
          AtSytle(NULL, 1, 2);
        } break;
        case 568: { // funlinkat
          FATPERMCHECK(NULL, W_OK | F_OK, 1, 2);
          AtSytle(NULL, 1, 2);
        } break;
        case 570:
          InterceptSysctlByname();
          break;
        case 572: // shm_rename
          InterceptShmRename();
          break;
        case 573: // sigfastblock
          goto defacto;
        case 574: // realpathat
        {
          // FATPERMCHECK(NULL, R_OK | F_OK, 0, 1);
          InterceptRealPathAt();
          break;
        }

        case 575: { // closerange
          CProcInfo *pinf = GetProcInfByPid(pid2);
          int a = GetArg(0);
          int b = GetArg(1);
          while (a < b) {
            FDCacheRem(pinf->fd_cache, a++);
          }
          FinishNormal();
          break;
        }
        default:;
        }
        goto defacto;
      } else {
      defacto:;
        if (WIFSTOPPED(cond)) {
          if (WSTOPSIG(cond) == SIGTRAP) {
            if(inf.pl_flags&(PL_FLAG_SCE|PL_FLAG_SCX)) {
				goto norm;
			}
          }
          ptrace(PT_TO_SCX,pid2,(caddr_t)1,WSTOPSIG(cond));
          
          DelegatePtraceEvent(pid2, cond,&mc_current_usage,&mc_current_siginfo);
          continue;
        }
      norm:
      syscall:;
        if(inf.pl_flags&PL_FLAG_SCE) {
          PT_SyscallExit();
        } else {
          PT_SyscallEnter();
        }
      }
    next:;
    }
  } else if (!tflag) {
    const char *dummy_argv[argc - 2 + 1 + 1];
    int64_t r, has_ld_preload;
    dummy_argv[0] = prog;
    for (idx = 0; idx != argc - 2; idx++)
      dummy_argv[idx + 1] = argv[idx + 2];
    dummy_argv[argc - 2 + 1] = NULL;
    ptrace(PT_TRACE_ME, pid, NULL, 0);
    GetChrootedPath(chroot_bin, prog);
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
    char *nenv[256], *xauth = NULL;
    has_ld_preload = 0;
    r = 0;
    for (int r2 = 0; env[r2]; r2++) {
      if (Startswith(env[r2], "XAUTHORITY=") && Xflag)
        continue;
      if (Startswith(env[r2], "LD_PRELOAD=") && 0) {
        has_ld_preload = 1;
        snprintf(nenv_d[r], sizeof *nenv_d, "%s %s", env[r2], "/" DLLNAME);
      } else
        strcpy(nenv_d[r], env[r2]);
      nenv[r] = nenv_d[r];
      r++;
    }
    if (!has_ld_preload) {
      sprintf(nenv_d[r], "LD_PRELOAD=/%s", DLLNAME);
      nenv[r] = nenv_d[r];
      r++;
    }
    if (Xflag) {
#define XAUTH_NAME ".XAuthority"
      if (xauth = getenv("XAUTHORITY")) {
        sprintf(nenv_d[r], "XAUTHORITY=/" XAUTH_NAME);
        nenv[r] = nenv_d[r];
        r++;
        int f, f2;
        if ((f = open(xauth, O_RDONLY)) >= 0) {
          f2 = open(XAUTH_NAME, O_WRONLY | O_CREAT, 0644);
          if (f2 >= 0) {
            copy_file_range(f, NULL, f2, NULL, SSIZE_MAX, 0);
            close(f2);
          }
          close(f);
        }
      }
    }

    nenv[r] = "LD_LIBRARY_PATH=/lib:/usr/lib:/usr/local/lib";
    r++;
    nenv[r] = NULL;
    execve(chroot_bin, dummy_argv, nenv);
  } else if (tflag) {
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
