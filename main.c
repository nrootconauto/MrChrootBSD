#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <kvm.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libprocstat.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>
#include "nrchroot.h"
typedef struct CMountPoint {
	struct CMountPoint *last,*next;
	char src_path[1024];
	char dst_path[1024];
} CMountPoint;
typedef struct CProcInfo {
	struct CProcInfo *last,*next;
	pid_t pid;
} CProcInfo;
CProcInfo proc_head;
CMountPoint mount_head,*root_mount;

//TODO account for pid(chroot/jail etc)
extern int64_t UnChrootPath(char *to,char *from);
int64_t GetProcCwd(char *to,pid_t pid) {
	unsigned int cnt=0,idx;
	int64_t res_cnt=0;
	char buf[1024];
	struct procstat *ps=procstat_open_sysctl();
	struct filestat_list *head;
	//See /usr/src/use.bin/procstat in FreeBSD
	struct filestat *thank_the_devas;
	struct kinfo_proc *kprocs=procstat_getprocs(ps,KERN_PROC_PID,pid,&cnt);
	for(idx=0;idx!=cnt;idx++) {
		head=procstat_getfiles(ps,kprocs,0);
		STAILQ_FOREACH(thank_the_devas, head, next) {
			if(thank_the_devas->fs_path&&thank_the_devas->fs_uflags&PS_FST_UFLAG_CDIR) {
				res_cnt=UnChrootPath(buf,thank_the_devas->fs_path);
				if(to) strcpy(to,buf);
				break;
			}
		}
		procstat_freefiles(ps,head);
	}
	procstat_freeprocs(ps,kprocs);
	procstat_close(ps);
	return res_cnt;
}

CMountPoint *AddMountPoint(const char *dst,const char *src) {
	CMountPoint *mp=calloc(sizeof(CMountPoint),1);
	strcpy(mp->src_path,src);
	realpath(dst,mp->dst_path);
	mp->next=mount_head.next;
	mp->last=&mount_head;
	mp->next->last=mp;
	mp->last->next=mp;
	return mp;
}

CProcInfo *GetProcInfByPid(pid_t pid) {
	CProcInfo *cur;
	for(cur=proc_head.next;cur!=&proc_head;cur=cur->next) {
		if(pid==cur->pid)
			return cur;
	}
	cur=calloc(sizeof(CProcInfo),1);
	cur->next=proc_head.next;
	cur->last=&proc_head;
	cur->next->last=cur;
	cur->last->next=cur;
	cur->pid=pid;
	return cur;
}
static char *StrMove(char *to,char *from) {
	int64_t len=strlen(from)+1;
	return memmove(to,from,len);
}
int64_t NormailizePath(char *to,const char *path) {
	int64_t idx;
	char result[1024];
	strcpy(result,path);
	for(idx=0;result[idx];idx++) {
		again:
		if(result[idx]=='/') {
			if(result[idx+1]=='/') {
				StrMove(&result[idx],&result[idx+1]);
				goto again;
			} else if(result[idx+1]=='.') {
				if(!result[idx+2]||result[idx+2]=='/') {
					StrMove(&result[idx+1],&result[idx+2]);
					goto again;
				}
			}
		}
	}
	if(!*result) strcpy(result,"/");
	if(to) strcpy(to,result);
	return strlen(result);
}
int64_t GetChrootedPath(char *to,pid_t pid,const char *path) {
	int64_t idx,max_match=0;
	char result[1024];
	char certified_lover_boy[1024];
	CProcInfo *pi=GetProcInfByPid(pid);
	CMountPoint *mp,*choose;
	struct ptrace_lwpinfo inf; 
	ptrace(PT_LWPINFO,pid,&inf,sizeof(inf));
	if(*path=='/')
		strcpy(result,"/");
	else {
		GetProcCwd(result,pid);
		strcat(result,"/");
	}
	strcat(result,path);
	NormailizePath(result,result);
	for(mp=mount_head.next;mp!=&mount_head;mp=mp->next) {
		//FORCE it to be normal(failsafe)
		NormailizePath(mp->src_path,mp->src_path);
		if(max_match<strlen(mp->src_path))
			if(!strncmp(mp->src_path,result,strlen(mp->src_path))) {
				max_match=strlen(mp->src_path);
				choose=mp;
			}
	}
	if(!choose) {
		fprintf(stderr,"Fucking ass poodles;unable to find mount point for \"%s\".\n",result);
		exit(1);
	}
	mp=choose;
	strcpy(certified_lover_boy,mp->dst_path);
	strcat(certified_lover_boy,"/");
	strcat(certified_lover_boy,&result[strlen(mp->src_path)]);
	NormailizePath(certified_lover_boy,certified_lover_boy);
	idx=strlen(certified_lover_boy);
	if(idx) 
		if(certified_lover_boy[idx-1]=='/')
			certified_lover_boy[idx-1]=0;
	if(to) strcpy(to,certified_lover_boy);
	return strlen(certified_lover_boy);
}
int64_t ReadPTraceString(char *to,pid_t pid,const int *pt_ptr) {
	int64_t idx,nul_check;
	char result[1024];
	for(idx=0;idx!=sizeof(result)/sizeof(int);idx++) {
		((int*)result)[idx]=ptrace(PT_READ_D,pid,pt_ptr,0);
		for(nul_check=0;nul_check!=sizeof(int);nul_check++) {
			if(!result[nul_check+idx*sizeof(int)])
			  goto pass;
		}
		pt_ptr++;
	}
	if(to) strcpy(to,"");
	return 0;
pass:
   if(to) strcpy(to,result);
   return (idx+1)*sizeof(int);
}
void PTraceRestoreBytes(pid_t pid,int *pt_ptr,const int *backup,int64_t backup_len) {
	int64_t ints=backup_len/sizeof(int),idx;
	for(idx=0;idx!=ints;idx++) {
		ptrace(PT_WRITE_D,pid,pt_ptr++,backup[idx]);
	}
}
void PTraceWriteBytes(pid_t pid,const int *pt_ptr,const char *st,int64_t len) {
	int64_t ints=(len+1)/sizeof(int);
	int64_t have,mask,idx;
	for(idx=0;idx!=ints;idx++) {
		ptrace(PT_WRITE_D,pid,pt_ptr++,((const int*)st)[idx]);
	}
	len=len%sizeof(int);
	if(len) {
		mask=(1ul<<(len*8))-1;
		have=(ptrace(PT_READ_D,pid,pt_ptr,0)&~mask)|(((const int*)st)[idx]&mask);
		ptrace(PT_WRITE_D,pid,pt_ptr,have);
	}
}
int64_t WritePTraceString(int *backup,pid_t pid,const int *pt_ptr,const char *st) {
	int64_t idx;
	int64_t ints=(strlen(st)+1)/sizeof(int);
	if((strlen(st)+1)%sizeof(int))
		ints++;
	for(idx=0;idx!=ints;idx++) {
		if(backup)
			backup[idx]=ptrace(PT_READ_D,pid,pt_ptr,0);
		ptrace(PT_WRITE_D,pid,pt_ptr,((const int*)st)[idx]);
		pt_ptr++;
	}
	return ints*sizeof(int);
}
void InterceptWrite(pid_t pid,const char *str) {
	return;
	char backupstr[1024];
	char have_str[1024];
	int64_t backup_len,olen;
	void *orig_ptr;
	if(ABIGetArg(pid,0)==1) { //stdout
		orig_ptr=(void*)ABIGetArg(pid,1);
		olen=ABIGetArg(pid,2);
		ReadPTraceString(have_str,pid,orig_ptr);
		ABISetArg(pid,2,strlen(str));
		backup_len=WritePTraceString(backupstr,pid,orig_ptr,str);
		ptrace(PT_TO_SCX,pid,(void*)1,0);
		waitpid(pid,NULL,0);
		PTraceRestoreBytes(pid,orig_ptr,backupstr,backup_len);
		ABISetReturn(pid,olen,0);
	}
}
#define INTERCEPT_FILE1(pid,arg) \
	char backupstr[1024]; \
	char have_str[1024],chroot[1023]; \
	int64_t backup_len,olen; \
	void *orig_ptr; \
	orig_ptr=(void*)ABIGetArg(pid,arg); \
	ReadPTraceString(have_str,pid,orig_ptr); \
	GetChrootedPath(chroot,pid,have_str); \
	backup_len=WritePTraceString(backupstr,pid,orig_ptr,chroot); \
	ptrace(PT_TO_SCX,pid,(void*)1,0); \
	waitpid(pid,NULL,0); \
	PTraceRestoreBytes(pid,orig_ptr,backupstr,backup_len);


#define INTERCEPT_FILE1_ONLY_ABS(pid,arg) \
	char backupstr[1024]; \
	char have_str[1024],chroot[1023]; \
	int64_t backup_len,olen; \
	void *orig_ptr; \
	orig_ptr=(void*)ABIGetArg(pid,arg); \
	ReadPTraceString(have_str,pid,orig_ptr); \
	if(have_str[0]=='/') {\
		GetChrootedPath(chroot,pid,have_str); \
		backup_len=WritePTraceString(backupstr,pid,orig_ptr,chroot); \
		ptrace(PT_TO_SCX,pid,(void*)1,0); \
		waitpid(pid,NULL,0); \
		PTraceRestoreBytes(pid,orig_ptr,backupstr,backup_len); \
	} else { \
		ptrace(PT_TO_SCX,pid,(void*)1,0); \
		waitpid(pid,NULL,0); \
	}

void InterceptRealPathAt(pid_t pid) {
	char backupstr[1024];
	char have_str[1024],chroot[1023];
	int64_t backup_len,olen;
	void *orig_ptr,*to_ptr;
	orig_ptr=(void*)ABIGetArg(pid,1);
	to_ptr=(void*)ABIGetArg(pid,2);
	ReadPTraceString(have_str,pid,orig_ptr);
	GetChrootedPath(chroot,pid,have_str); 
	ptrace(PT_TO_SCX,pid,(void*)1,0);
	waitpid(pid,NULL,0);
	UnChrootPath(chroot,chroot);
	PTraceWriteBytes(pid,to_ptr,chroot,strlen(chroot)+1);
	ABISetReturn(pid,0,0);
}

void InterceptAccess(pid_t pid) {
	INTERCEPT_FILE1(pid,0);
}

void InterceptOpen(pid_t pid) {
	INTERCEPT_FILE1(pid,0);
}

void InterceptExecve(pid_t pid) {
	char have_str[1024],chroot[1024],backup[1024];
	void *orig_ptr,*argv,*env;
	int64_t fd,args[3],bulen;
	struct ptrace_sc_remote rmt;
	orig_ptr=(void*)ABIGetArg(pid,0); 
	argv=(void*)ABIGetArg(pid,1);
	env=(void*)ABIGetArg(pid,2);
	ReadPTraceString(have_str,pid,orig_ptr);
	GetChrootedPath(chroot,pid,have_str);
	ABISetSyscall(pid,5);
	ABISetArg(pid,1,O_EXEC);
	bulen=WritePTraceString(backup,pid,orig_ptr,chroot);
	ptrace(PT_TO_SCX,pid,(void*)1,0);
	waitpid(pid,NULL,0);
	PTraceRestoreBytes(pid,orig_ptr,backup,bulen);
	args[0]=ABIGetReturn(pid,NULL);
	args[1]=(int64_t)argv;
	args[2]=(int64_t)env;
	rmt.pscr_syscall=492;
	rmt.pscr_nargs=3;
	rmt.pscr_args=args;
	ptrace(PT_SC_REMOTE,pid,&rmt,sizeof(rmt));
}

int64_t UnChrootPath(char *to,char *from) {
	char buf[1024];
	CMountPoint *mp,*best=root_mount;
	int64_t trim,best_len=0xffff,len;
	for(mp=mount_head.next;mp!=&mount_head;mp=mp->next) {
		len=strlen(mp->dst_path);
		if(!strncmp(from,mp->dst_path,len)) {
			if(best_len<len) {
				best_len=len;
				best=mp;
			}
		}
	}
	
	trim=strlen(best->dst_path);
	strcpy(buf,"/");
	StrMove(&buf[1],&from[trim]);
	if(to) strcpy(to,buf);
	return strlen(buf);
}

void InterceptReadlink(pid_t pid) {
	char new_path[1024],got_path[1024],backup[1024];
	char rlbuf[1024];
	int64_t backup_len,buf_len,r,trim;
	void *orig_ptr=(void*)ABIGetArg(pid,0),*buf_ptr=(void*)ABIGetArg(pid,2);
	buf_len=ABIGetArg(pid,1);
	ReadPTraceString(got_path,pid,orig_ptr);
	GetChrootedPath(new_path,pid,got_path);
	backup_len=WritePTraceString(backup,pid,orig_ptr,new_path);
	ptrace(PT_TO_SCX,pid,(void*)1,0);
	waitpid(pid,NULL,0);
	PTraceRestoreBytes(pid,orig_ptr,backup,backup_len);
		
	r=readlink(new_path,rlbuf,1024);
	UnChrootPath(rlbuf,new_path);
	PTraceWriteBytes(pid,buf_ptr,rlbuf,strlen(rlbuf)+1);
	ReadPTraceString(got_path,pid,buf_ptr);
	if(r<0) {
	  ABISetReturn(pid,r,1);
	} else {
	  r=strlen(rlbuf);
	  ABISetReturn(pid,r,0);
	}
}

void InterceptReadlinkAt(pid_t pid) {
	char new_path[1024],got_path[1024],backup[1024];
	char rlbuf[1024];
	int64_t backup_len,buf_len=ABIGetArg(pid,3),r,trim;
	void *orig_ptr=(void*)ABIGetArg(pid,1),*buf_ptr=(void*)ABIGetArg(pid,2);
	ReadPTraceString(got_path,pid,orig_ptr);
	if(*got_path=='/') {
		GetChrootedPath(new_path,pid,got_path);
		backup_len=WritePTraceString(backup,pid,orig_ptr,new_path);
		ptrace(PT_TO_SCX,pid,(void*)1,0);
		waitpid(pid,NULL,0);
		PTraceRestoreBytes(pid,orig_ptr,backup,backup_len);
	} else {
		ptrace(PT_TO_SCX,pid,(void*)1,0);
		waitpid(pid,NULL,0);
		ReadPTraceString(new_path,pid,buf_ptr);
	}
	r=readlink(new_path,rlbuf,1024);
	if(r<0)
	  ABISetReturn(pid,r,1);
	else {
	  UnChrootPath(rlbuf,new_path);
	  r=strlen(rlbuf);
	  PTraceWriteBytes(pid,buf_ptr,rlbuf,r);
	  ABISetReturn(pid,r,0);
	}
}

#define INTERCEPT_FILE2(pid,arg1,arg2) \
	char backup1[1024],chroot1[1024],got1[1024]; \
	char backup2[1024],chroot2[1024],got2[1024]; \
	void *orig_ptr1=(void*)ABIGetArg(pid,arg1); \
	void *orig_ptr2=(void*)ABIGetArg(pid,arg2); \
	char *dumb_ptr=orig_ptr1; /*write 2 strings to  1 pointer in case orig_ptr1/orig_ptr2 overlap(chrooted strings are larger than originals)*/  \
	int64_t backup_len1,backup_len2; \
	ReadPTraceString(got1,pid,orig_ptr1);  \
	ReadPTraceString(got2,pid,orig_ptr2);  \
	GetChrootedPath(chroot1,pid,got1);  \
	GetChrootedPath(chroot2,pid,got2);  \
	/*  \
	//[chroot1\0chroot2\0] \
	//          ^    \
	//          |	 \
	//          + Arg1 is here*/  \
	dumb_ptr=orig_ptr1; \
	backup_len1=WritePTraceString(backup1,pid,orig_ptr1,chroot1); \
	dumb_ptr+=backup_len1; \
	backup_len2=WritePTraceString(backup2,pid,dumb_ptr,chroot2); \
	ABISetArg(pid,1,(int64_t)dumb_ptr); /*Re-assign poo poo address*/ \
	ptrace(PT_TO_SCX,pid,(void*)1,0); \
	waitpid(pid,NULL,0);  \
	PTraceRestoreBytes(pid,orig_ptr1,backup1,backup_len1); \
	PTraceRestoreBytes(pid,dumb_ptr,backup2,backup_len2);

void InterceptLink(pid_t pid) {
	INTERCEPT_FILE2(pid,0,1);
}

void InterceptUnlink(pid_t pid) {
	INTERCEPT_FILE1(pid,0);
}

void InterceptShmRename(pid_t pid) {
	INTERCEPT_FILE2(pid,0,1);
}




void InterceptChdir(pid_t pid) {
	char backupstr[1024];
	char have_str[1024],chroot[1023];
	int64_t backup_len,olen;
	void *orig_ptr;
	orig_ptr=(void*)ABIGetArg(pid,0);
	ReadPTraceString(have_str,pid,orig_ptr);
	GetChrootedPath(chroot,pid,have_str);
	backup_len=WritePTraceString(backupstr,pid,orig_ptr,chroot);
	ptrace(PT_TO_SCX,pid,(void*)1,0);
	waitpid(pid,NULL,0);
	PTraceRestoreBytes(pid,orig_ptr,backupstr,backup_len);
}

void Intercept__Getcwd(pid_t pid) {
	int64_t olen,cap;
	void *orig_ptr;
	char cwd[1024];
	olen=GetProcCwd(cwd,pid);
	orig_ptr=(void*)ABIGetArg(pid,0);
	cap=ABIGetArg(pid,1);
	ptrace(PT_TO_SCX,pid,(void*)1,0);
	waitpid(pid,NULL,0);
	PTraceWriteBytes(pid,orig_ptr,cwd,cap>olen+1?olen+1:cap);
	ABISetReturn(pid,0,0);
}


void InterceptMount(pid_t pid) {
	//TODO
}

void InterceptUnmount(pid_t pid) {
	//TODO
}

void InterceptNmount(pid_t pid) {
	//TODO
}

void InterceptAccessShmUnlink(pid_t pid) {
	INTERCEPT_FILE1(pid,0);
}

void InterceptAccessTruncate(pid_t pid) {
	INTERCEPT_FILE1(pid,0);
}

struct stat;

void InterceptFstat(pid_t pid) {
	//makes the file look like it was made by root (TODO enable/disable this from command line)
	char *ptr=(void*)ABIGetArg(pid,1);
	int64_t o1=offsetof(struct stat,st_uid),o2=offsetof(struct stat,st_gid);
	ptrace(PT_TO_SCX,pid,(void*)1,0);
	waitpid(pid,NULL,0);
	ptrace(PT_WRITE_D,pid,ptr+o1,0);
	ptrace(PT_WRITE_D,pid,ptr+o2,0);
}

void InterceptFhstat(pid_t pid) {
	//makes the file look like it was made by root (TODO enable/disable this from command line)
	char *ptr=(void*)ABIGetArg(pid,1);
	int64_t o1=offsetof(struct stat,st_uid),o2=offsetof(struct stat,st_gid);
	ptrace(PT_TO_SCX,pid,(void*)1,0);
	waitpid(pid,NULL,0);
	ptrace(PT_WRITE_D,pid,ptr+o1,0);
	ptrace(PT_WRITE_D,pid,ptr+o2,0);
}

void InterceptFstatat(pid_t pid) {
	//makes the file look like it was made by root (TODO enable/disable this from command line)
	char *statp=(void*)ABIGetArg(pid,2);
	int64_t o1=offsetof(struct stat,st_uid),o2=offsetof(struct stat,st_gid);
	INTERCEPT_FILE1_ONLY_ABS(pid,1);
	ptrace(PT_WRITE_D,pid,statp+o1,0);
	ptrace(PT_WRITE_D,pid,statp+o2,0);
}

static void FakeGroup(pid_t pid) {
	ptrace(PT_TO_SCX,pid,(void*)1,0);
	waitpid(pid,0,0);
	ABISetReturn(pid,0,0);					
}

static void FakeUser(pid_t pid) {
	ptrace(PT_TO_SCX,pid,(void*)1,0);
	waitpid(pid,0,0);
	ABISetReturn(pid,0,0);					
}

//Fakes a succeffusl return
static void FakeSuccess(pid_t pid) {
	ptrace(PT_TO_SCX,pid,(void*)1,0);
	waitpid(pid,0,0);
	ABISetReturn(pid,0,0);						
}

int main(int argc,const char **argv,const char **env) {
	pid_t pid,pid2;
	int64_t idx;
	char chroot_bin[1024];
	CProcInfo *pnext,*plast;
	if(argc<3) {
		fprintf(stderr,"Usage slim_jail [chroot] [shell] ...");
		exit(1);
	}
	proc_head.last=&proc_head;
	proc_head.next=&proc_head;
	
	mount_head.last=&mount_head;
	mount_head.next=&mount_head;

	root_mount=AddMountPoint(argv[1],"/");
	AddMountPoint("/dev","/dev");
	
	if(pid=fork()) {
		int cond;
		while(pid2=waitpid(-1,&cond,WUNTRACED)) {
			if(WIFEXITED(cond)&&pid2==pid)
				exit(0);
			struct ptrace_lwpinfo inf; 
			ptrace(PT_LWPINFO,pid2,&inf,sizeof(inf));
			if(WIFEXITED(cond)) {
				continue;
			} else if(WIFSIGNALED(cond)) {
				ptrace(PT_CONTINUE,pid2,(void*)1,WTERMSIG(cond));
				continue;
			} else if(WIFSTOPPED(cond)) {
				//I probably did this(ptrace did it)
				if(WSTOPSIG(cond)==SIGTRAP)
					goto normal;
				//Also from ptrace probably
				if(WSTOPSIG(cond)==SIGSTOP)
					goto normal;
				ptrace(PT_CONTINUE,pid2,(void*)1,WSTOPSIG(cond));
				continue;
				
			}
normal:
			ptrace(PT_FOLLOW_FORK,pid2,NULL,1);
			if(inf.pl_flags&PL_FLAG_CHILD) {
				struct ptrace_sc_remote rmt;
				int64_t args[1];
				args[0]=0; //root
				rmt.pscr_args=args;
				rmt.pscr_nargs=1;
				rmt.pscr_syscall=183; //seteuid
				ptrace(PT_SC_REMOTE,pid2,&rmt,sizeof(rmt));
				ptrace(PT_TO_SCX,pid2,(void*)1,0);
				waitpid(pid2,NULL,0);
				args[0]=0; //wheel
				rmt.pscr_args=args;
				rmt.pscr_nargs=1;
				rmt.pscr_syscall=182; //setegid
				ptrace(PT_SC_REMOTE,pid2,&rmt,sizeof(rmt));
				ptrace(PT_TO_SCX,pid2,(void*)1,0);
				waitpid(pid2,NULL,0);
			}
			if(inf.pl_flags&PL_FLAG_SCE) {
				switch(inf.pl_syscall_code) {
					case 1: //exit
					ptrace(PT_DETACH,pid2,NULL,0);
					break;
					case 2: //fork
					break; 
					case 3: //read
					break;
					case 4: //write
					break;
					case 5: //open
					InterceptOpen(pid2);
					break;
					case 6: //close
					break;
					case 7: //fork
					break;
					case 9: //link
					InterceptLink(pid2);
					break;
					case 10: //unlink
					InterceptUnlink(pid2);
					break;
					case 12: { //chdir
						InterceptChdir(pid2);
					}
					case 13://fdchdir
					break;
					case 20: //getpid 
					break;
					case 21: //mount
					InterceptMount(pid2);
					break;
					case 22: //unmount
					InterceptUnmount(pid2);
					break;
					case 23: //setuid
					FakeSuccess(pid2);
					break;
					case 24: //getuid
					FakeUser(pid2);
					break;
					case 25://geteuid
					FakeUser(pid2);
					break;
					case 33: //access
					InterceptAccess(pid2);
					break;
					case 34: { //chflags
						INTERCEPT_FILE1(pid,0);
					}
					break;
					case 39: //getppid TODO
					break;
					case 41: //dup
					break;
					case 43: {//getegid
						FakeGroup(pid2);
					}
					break;
					case 47: {//getgid
						FakeGroup(pid2);
					}
					break;
					case 54: //ioctl
					break;
					case 56: {//revoke
						INTERCEPT_FILE1(pid2,0);
					}
					break;
					case 57: {//symlink
						INTERCEPT_FILE2(pid2,0,1);
					}
					break;
					case 58: //readlink
					InterceptReadlink(pid2);
					break;
					case 59: //execve
					InterceptExecve(pid2);
					break;
					case 61: //chroot TODO
					case 73: //munmap
					break;
					case 74: //mprotect
					break;
					case 81: //getpgrp TODO
					break;	
					case 82: //setpgid TODO
					break;
					case 83: //setitimer
					break;
					case 85: //swapon
					//no way
					break;
					case 92: //fcntl
					break;
					case 93: //select
					break;
					//Fake the chown homies as we are "root"
					case 15: //chmod
					case 16: //chown
					case 123: //fchmod
					case 124: //fchown
					FakeSuccess(pid2);
					break;
					case 126: //setreuid
					FakeSuccess(pid2);
					break; 
					case 127: //setregid
					FakeSuccess(pid2);
					break; 
					case 128: { //rnemae
						INTERCEPT_FILE2(pid2,0,1);
					}
					break;
					case 132: {//mkdifof
						INTERCEPT_FILE1(pid2,0);
					}
					break;
					case 136 ... 138:  {//mkdir/rmdir/utimes
						INTERCEPT_FILE1(pid2,0);
					}
					break;
					case 147: //setsid TODO?
					break; 
					case 148: { //qoutactl
						INTERCEPT_FILE1(pid2,0);
					}
					break;
					case 161 ... 162:  {//lgetfh
						INTERCEPT_FILE1(pid2,0);
					}
					break;
					case 165: //sysarch
					break;
					case 181: //getgid
					FakeGroup(pid2);
					break;
					case 182: //setegid
					FakeGroup(pid2);
					break;
					case 183: //seteuid
					FakeSuccess(pid2);
					break;
					case 191: { //pathconf
						INTERCEPT_FILE1(pid2,0);
					}
					break;
					case 204: { //undelete
						INTERCEPT_FILE1(pid2,0);
					}
					break;
					case 207: //getpgid TODO
					break;
					case 253: //issetugid TODO
					break;
					case 254: {//lchown
						INTERCEPT_FILE1(pid2,0); //This exits the syscall for us
						ABISetReturn(pid2,0,0);
					}
					break;
					case 274: {//luchmod
						INTERCEPT_FILE1(pid2,0);
						ABISetReturn(pid2,0,0); //The syscall has exited if here
					}
					break;
					case 276: { //lutimes
						INTERCEPT_FILE1(pid2,0);
					}
					break;
					case 326: //getcwd
					Intercept__Getcwd(pid2);
					break;
					case 338: //jail TODO
					break;
					case 340: //sigprocmask
					break;
					//__acl_xxxx_file
					case 347:
					case 348:
					case 351:
					case 353: {
						INTERCEPT_FILE1(pid2,0);
					}
					break;
					case 356 ... 358: { //	extattr_set_file	extattr_get_file	extattr_delete_file
						INTERCEPT_FILE1(pid2,0);
					}
					case 376: { //eaccess
						INTERCEPT_FILE1(pid2,0);
					}
					break;
					case 378: //nmount
					InterceptNmount(pid2);
					break;
					case 387: case 389: { //__mac_get_file/__mac_set_file
						INTERCEPT_FILE1(pid2,0);
					}
					break;
					case 391: { //lchflags
						INTERCEPT_FILE1(pid2,0);
					}
					break;
					case 409: case 411: { //mac_get_link/set_link
						INTERCEPT_FILE1(pid2,0);
					}
					break;
					case 412 ... 414: { //extattr_set_link/get_link/delete_link
						INTERCEPT_FILE1(pid2,0);
					}
					break;
					case 416: //sigaction
					break; 	
					case 417: //sigreturn
					break;
					case 436: //jail_attach
					break; 
					case 475: //pread
					break;
					case 476: //pwrite
					break;
					case 477: //mmap
					break;
					case 479: //shm_unlink
					InterceptAccessTruncate(pid2);
					break;
					case 483: //shm_unlink
					InterceptAccessShmUnlink(pid2);
					break;
					case 500: //readlinkat
					InterceptReadlinkAt(pid2);
					break;
					case 489 ... 499: //openat xxx_at
					case 503:
					{
						INTERCEPT_FILE1_ONLY_ABS(pid2,1); //This exits the syscall for us
						//TODO check if "root"
						if(inf.pl_syscall_code==490||inf.pl_syscall_code==491)
							ABISetReturn(pid2,0,0);
					}
					break;
					case 501: { //renameat
						pid_t pid=pid2;
						char backupstr[1024],backupstr2[1024];
						char have_str[1024],chroot[1023],have_str2[1024],chroot2[1024];
						int64_t backup_len=-1,backup_len2=-1;
						char *orig_ptr,*orig_ptr2,*dumb_to;
						orig_ptr=(void*)ABIGetArg(pid,1);
						orig_ptr2=(void*)ABIGetArg(pid,3);
						ReadPTraceString(have_str,pid,orig_ptr);
						ReadPTraceString(have_str2,pid,orig_ptr2);
						dumb_to=orig_ptr2;
						if(have_str[0]=='/') {
							GetChrootedPath(chroot,pid,have_str);
							backup_len=WritePTraceString(backupstr,pid,orig_ptr,chroot);
							dumb_to=orig_ptr+backup_len+1;
						} else {
							dumb_to=orig_ptr+strlen(have_str)+1;
						} 
						
						//orig_ptr[0]orig_ptr's string
						if(have_str2[0]=='/') {
							GetChrootedPath(chroot2,pid,have_str2);
							backup_len2=WritePTraceString(backupstr2,pid,dumb_to,chroot2);
						} else 
							backup_len2=WritePTraceString(backupstr2,pid,dumb_to,have_str2);
						ABISetArg(pid,3,(uint64_t)dumb_to);
						
						ptrace(PT_TO_SCX,pid,(void*)1,0);
						waitpid(pid,NULL,0);
						
						if(backup_len!=-1)
						  PTraceRestoreBytes(pid,orig_ptr,backupstr,backup_len);
						if(backup_len2!=-1)
						  PTraceRestoreBytes(pid,dumb_to,backupstr2,backup_len2);
					}
					break;
					case 502: { //symlinkat
						pid_t pid=pid2;
						char backupstr[1024],backupstr2[1024];
						char have_str[1024],chroot[1023],have_str2[1024],chroot2[1024];
						int64_t backup_len=-1,backup_len2=-1;
						char *orig_ptr,*orig_ptr2,*dumb_to;
						orig_ptr=(void*)ABIGetArg(pid,0);
						orig_ptr2=(void*)ABIGetArg(pid,2);
						ReadPTraceString(have_str,pid,orig_ptr);
						ReadPTraceString(have_str2,pid,orig_ptr2);
						dumb_to=orig_ptr2;
						if(have_str[0]=='/') {
							GetChrootedPath(chroot,pid,have_str);
							backup_len=WritePTraceString(backupstr,pid,orig_ptr,chroot);
							dumb_to=orig_ptr+backup_len+1;
						} else {
							dumb_to=orig_ptr+strlen(have_str)+1;
						} 
						//orig_ptr[0]orig_ptr's string
						if(have_str2[0]=='/') {
							GetChrootedPath(chroot2,pid,have_str2);
							backup_len2=WritePTraceString(backupstr2,pid,dumb_to,chroot2);
						} else 
							backup_len2=WritePTraceString(backupstr2,pid,dumb_to,have_str2);
						ABISetArg(pid,2,(uint64_t)dumb_to);
						
						
						ptrace(PT_TO_SCX,pid,(void*)1,0);
						waitpid(pid,NULL,0);
						
						if(backup_len!=-1)
						  PTraceRestoreBytes(pid,orig_ptr,backupstr,backup_len);
						if(backup_len2!=-1)
						  PTraceRestoreBytes(pid,dumb_to,backupstr2,backup_len2);
					}
					break;
					case 506 ... 508: //jail shit. TODO
					break;
					case 551: //fstat
					InterceptFstat(pid2);
					break;
					case 552: //fstatat
					InterceptFstatat(pid2);
					break;
					case 553:
					InterceptFhstat(pid2);
					break;
					case 554: //getdirentries 
					//Filename is from fd
					break;
					case 540: //chflagsat
					break;
					case 547: //utimensat "touch"
					{
						INTERCEPT_FILE1_ONLY_ABS(pid2,1);
					}
					break;
					break;
					case 557: //getfsstat TODO
					break;
					case 559: { //mknodat
						INTERCEPT_FILE1_ONLY_ABS(pid2,1);
					}
					break;
					case 563: //getrandom
					break;
					case 564: { //getfhat
						INTERCEPT_FILE1_ONLY_ABS(pid2,1);
					}
					break;
					case 565: { //fhlink
						INTERCEPT_FILE1(pid2,1);
					}
					break;
					case 566: { //fhlinkat
						INTERCEPT_FILE1_ONLY_ABS(pid2,2);
					}
					break;
					case 568: { //funlinkat
						INTERCEPT_FILE1_ONLY_ABS(pid2,1);
					}
					break;
					case 572: //shm_rename
					InterceptShmRename(pid2);
					break;
					case 573: //sigfastblock
					break;
					case 574: //realpathat
					{
						InterceptRealPathAt(pid2);
					}
					default:
				}
			}
			ptrace(PT_TO_SCE,pid2,(void*)1,0);
		}
	} else {
		const char *dummy_argv[argc-3+1+1];
		char buf[1024];
		FILE *f,*f2;
		int64_t r,has_ld_preload;
		dummy_argv[0]=argv[2];
		for(idx=0;idx!=argc-3;idx++) {
			dummy_argv[idx+1]=argv[idx+3];
		}
		dummy_argv[argc-3+1]=NULL;
		ptrace(PT_TRACE_ME,pid,NULL,0);
		GetChrootedPath(chroot_bin,pid,argv[2]);
		//Add libpl_hack.so to the chroot to patch elf_aux_info
		if(access("libpl_hack.so",F_OK)) {
			fprintf(stderr,"I need the libpl_hack.so file to patch elf_aux_info please.\n");
			exit(1);
		}
		f=fopen("libpl_hack.so","rb");
		chdir(argv[1]);
		f2=fopen("libpl_hack.so","wb");
		while((r=fread(buf,1,1024,f))>0) 
			fwrite(buf,r,1,f2);
		fclose(f);
		fclose(f2);
		chmod("libpl_hack.so",
			S_IXGRP|S_IXUSR|S_IXOTH|
			S_IRGRP|S_IRUSR|S_IROTH|
			S_IWUSR);
		char nenv_d[1024][256];
		char *nenv[256];
		has_ld_preload=0;
		for(r=0;env[r];r++) {
			if(!strncmp("LD_PRELOAD=",env[r],strlen("LD_PRELOAD="))) {
				has_ld_preload=1;
				sprintf(&nenv_d[r],"%s %s",env[r],"/libpl_hack.so");
			} else
				strcpy(&nenv_d[r],env[r]);
			nenv[r]=&nenv_d[r];
		}
		if(!has_ld_preload) {
			strcpy(&nenv_d[r],"LD_PRELOAD=/libpl_hack.so");
			nenv[r]=&nenv_d[r];
			r++;
		}
		nenv[r]=NULL;
		execve(chroot_bin,dummy_argv,nenv);
	}
}
