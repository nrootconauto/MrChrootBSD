#include <sys/types.h>
#include <sys/ptrace.h>
#if defined(__x86_64__)
int64_t ABIGetReturn(pid_t pid,char *failed) {
	struct reg regs;
	ptrace(PT_GETREGS,pid,&regs,&regs);
	if(failed) *failed=regs.r_rflags&1; //Carry flag
	return regs.r_rax;
}
void ABISetReturn(pid_t pid,int64_t r,char failed) {
	struct reg regs;
	ptrace(PT_GETREGS,pid,&regs,&regs);
	regs.r_rdx=0;
	regs.r_rax=r;
	if(failed) regs.r_rflags|=1; //Carry flag
	else regs.r_rflags&=~1ul;
	ptrace(PT_SETREGS,pid,&regs,&regs);
}

void ABISetSyscall(pid_t pid,int64_t r) {
	struct reg regs;
	ptrace(PT_GETREGS,pid,&regs,&regs);
	regs.r_rdx=0;
	regs.r_rax=r;
	ptrace(PT_SETREGS,pid,&regs,&regs);
}


int64_t ABIGetArg(pid_t pid,int64_t arg) {
	int64_t stk_ptr;
	struct reg regs;
	ptrace(PT_GETREGS,pid,&regs,&regs);
	switch(arg) {
		case 0:
			return regs.r_rdi;
		case 1:
			return regs.r_rsi;
		case 2:
			return regs.r_rdx;
		case 3:
			return regs.r_rcx;
		case 4:
			return regs.r_r8;
		case 5:
			return regs.r_r9;
		default:
			stk_ptr=regs.r_rsp+8*(arg-6);
			return (ptrace(PT_READ_D,pid,stk_ptr,0)&0xffFFffFFul)|(ptrace(PT_READ_D,pid,stk_ptr+4,0)<<32ul);
	}
}
void ABISetArg(pid_t pid,int64_t arg,uint64_t val) {
	int64_t stk_ptr;
	struct reg regs;
	ptrace(PT_GETREGS,pid,&regs,&regs);
	switch(arg) {
		case 0:
			regs.r_rdi=val;
			break;
		case 1:
			regs.r_rsi=val;
			break;
		case 2:
			regs.r_rdx=val;
			break;
		case 3:
			regs.r_rcx=val;
			break;
		case 4:
			regs.r_r8=val;
			break;
		case 5:
			regs.r_r9=val;
			break;
		default:
			stk_ptr=regs.r_rsp+8*(arg-6);
			ptrace(PT_WRITE_D,pid,stk_ptr,val&0xffFFffFFul);
			ptrace(PT_WRITE_D,pid,stk_ptr+4,val>>32ul);
			break;
	}
	if(arg<=5)
		ptrace(PT_SETREGS,pid,&regs,&regs);
}
#endif
