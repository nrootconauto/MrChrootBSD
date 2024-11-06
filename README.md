# MrChrootBSD
  This program is a chroot like utility for FreeBSD,which is by far the most sexy BSD available. I like [PRoot](https://proot-me.github.io/) for testing software(on linux) but I am anaware of such a tool for FreeBSD,so I was left in the dust. Meet `MrChrootBSD`,a **non-root version of chroot** sort of.

# NOTICE

  **This software is going under major refactors including perimision emulation. Expect something juicy next week. Dont use it for anything serious now(or at all).**


## Features
  Here is a list
- Do chroot in userspace
- Partial `ptrace` emulation(limited,you can run `gdb` in your MrChroot's sort of and it will make you happy maybe)
- (Currently) buggy user permisions database(`perms.db` using `db(3)`)
- X11 within MrChrootBSD easily with the `-X` option.

## Non-Features
  Some of these will be removed(added to features) in the future
- Full `ptrace` emulation(Dont rely on `PT_TO_SCE`/`PT_TO_SCX` to work).
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
./mchroot -t base.txz chroot # Accounts for perms.db database
./mchroot -t lib32.txz chroot # Accounts for perms.db database
./mchroot chroot /bin/sh
# pkg etc
``` 

### X11 within MrChrootBSD

  Use `-X` option to allow /var/run and XAUTHORITY to be set so you can run X11 apps.

## Things to do after chroot'ing
### Copy `/etc/resolv.conf` into `/etc`.
  You'll want to do this for networking
### passwd root and install daos
  su wont work for now(if ever). doas works like a charm when configured correctly.
  ```sh
  pkg install doas
  echo 'permit nopass :wheel' > /usr/local/etc/doas.conf
  adduser -Z
  ```
  **MAKE SURE TO USE -Z with adduser TO NOT MAKE A ZFS dataset.**
## How it works internally

  It uses `ptrace` to intercept the calls and reroute the file names to the *host* filesystem. Certian caeveats such as FreeBSD using the host filesystem for `execvpe` or telling the full path of the executable via `elf_aux_info`  are patched in a `LD_PRELOAD` library called `libpl_hack.so` in `preload_hack.c`.

## Development Please ;)
I could use help in these areas,I will probably get them done myself but if you want to make my day:

 1. Add support for `riscv64` and `arm64` in `abi.c`.
 2. Make the tool extremely fun to use(have emojis and stuff)
 3. Implement` procctl(3)` reapers.
 4. Make sure `wait(2)` actually works(probably does)
 5. Validate existing `sysctl(3)` stuff(Probably works).
 6. **MAKE A ROBUST WAY TO TEST OF A PATH IS CHROOTED/UNCHROOTED**(like make the paths start with '\01' or '\02')
