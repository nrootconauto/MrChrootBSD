# MrChrootBSD
  This program is a chroot like utility for FreeBSD,which is by far the most sexy BSD available. I like [PRoot](https://proot-me.github.io/) for testing software(on linux) but I am anaware of such a tool for FreeBSD,so I was left in the dust. Meet `MrChrootBSD`,a **non-root version of chroot** sort of.

# NOTICE

  **This software is still in it's infancy and should not be used for anything serious other than like educational stuff.**

## Features
  Here is a list
- Do chroot in userspace
- (Currently) buggy user permisions database(`perms.db` using `db(3)`)
- X11 within MrChrootBSD easily with the `-X` option.
- Use `gdb` to debug stuff within the MrChrootBSD(limited `ptrace` support)
- **THIS IS MAINLY A HUMANS ATTEMPT TO LOOK AT FreeBSD INTERNALS(Educational)**

## Non-Features
  Some of these will be removed(added to features) in the future
- jails
- daemons

## Usage
This is early in development so stay tuned,use it like a normal chroot. Feel free to probe around the source code and send patches to my github.

```sh
git clone https://github.com/nrootconauto/MrChrootBSD.git
cd MrChrootBSD
wget https://download.freebsd.org/releases/amd64/14.1-RELEASE/base.txz
wget https://download.freebsd.org/releases/amd64/14.1-RELEASE/lib32.txz #Needed for gdb for some reason
mkdir chroot
cd ..
cmake .
make
cp /etc/resolv.conf chroot/etc # networking
./mrchroot -t base.txz chroot # Accounts for perms.db database
./mrchroot -t lib32.txz chroot # Accounts for perms.db database
./mrchroot chroot /bin/sh
# pkg etc
``` 

### X11 within MrChrootBSD

  Use `-X` option to allow /var/run and XAUTHORITY to be set so you can run X11 apps.

## Things to do after chroot'ing

### Copy `/etc/resolv.conf` into `/etc`.

  You'll want to do this for networking

### passwd root and install daos
  `su` wont work for now(if ever). `doas` works like a charm when configured correctly.
  ```sh
  pkg install doas
  echo 'permit nopass :wheel' > /usr/local/etc/doas.conf
  adduser -Z
  ```
  **MAKE SURE TO USE -Z with adduser TO NOT MAKE A ZFS dataset.**
## How it works internally

  It uses `ptrace` to intercept the calls and reroute the file names to the *host* filesystem. Certian caeveats such as FreeBSD using the host filesystem for `execvpe` or telling the full path of the executable via `elf_aux_info`  are patched in a `LD_PRELOAD` library called `libpl_hack.so` in `preload_hack.c`.

### Pt.1 System Calls Mutation

  The main "loop" of MrChrootBSD is in main which waits for syscall exits. When entering a syscall,you can do these

```c
COnSyscallExit *osce=FinishNormal();
osce=FinishPass0();
osce=FinishPass1(value);
osce=FinishFail(-errno);
```

  This will run trigger a callback when the syscall for `mc_current_tid` is exited,and will do lit stuff like change the retyurn values,or restore bytes of memory.

  MrChroot will insert "chrooted" filepaths in when enterin' syscalls,and will restore the original values on syscall exit,do this:

```c
osce=FinishPass0();
//You can restore 2 streams of bytes on 1 exit
OnSyscallExitSetBackup1(osce,ptr,bytes_to_restore,len);
OnSyscallExitSetBackup2(osce,ptr,bytes_to_restore,len);
```

### Pt.2 Chrooted x Unchrooted Paths

  When chrooting paths,you might get them mixed up,MrChroot does poo poo sauce checking after the ending of strings(it checks for `MC_CHROOTED_ENDING` x `MC_UNCHROOTED_ENDING`).

  You porbably can ignore this,just use the `C` and `U` functions.

```c
char path[1024];
strcpy(path,"/tmp")
char *path_ptr=C(path);
char *unchrooted=U(path);
```

### Pt.3 The Permisions table

  Look at hash.h,this stores file permisions x ownership.

```c
/* ... */
class(CHashEntry) {
	uint32_t perms;
	uid_t uid;
	gid_t gid;
};
void HashTableSet(const char *fn,uid_t u,gid_t g,uint32_t perms);
CHashEntry *HashTableGet(CHashEntry *e,const char *fn);
void HashTableRemove(const char *fn);
/* ... */
```

## Development Please ;)
I could use help in these areas,I will probably get them done myself but if you want to make my day:

 1. Add support for `riscv64` and `arm64` in `abi.c`.
 2. Make sure `wait(2)` actually works(probably does)
 3. Validate existing `sysctl(3)` stuff(Probably works).
 4. Write unit tests.
