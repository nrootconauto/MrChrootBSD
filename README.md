# MrChrootBSD
  This program is a chroot like utility for FreeBSD,which is by far the most sexy BSD available. I like [PRoot](https://proot-me.github.io/) for testing software(on linux) but I am anaware of such a tool for FreeBSD,so I was left in the dust. Meet `MrChrootBSD`,a **non-root version of chroot** sort of.

## Usage
This is early in development so stay tuned.

```sh
wget https://download.freebsd.org/releases/amd64/14.0-RELEASE/base.txz
mkdir chroot
cd chroot 
tar xvf ../base.txz
cd ..
cmake .
make
cp /etc/resolv.conf /etc # networkring
./mrhcroot chroot /bin/sh
# pkg etc
``` 
## Things to do after chroot'ing
### Copy `/etc/resolv.conf` into `/etc`.
  You'll want to do this for networking
## How it works internally
It uses `ptrace` to intercept the calls and reroute the file names to the *host* filesystem. Certian caeveats such as FreeBSD using the host filesystem for `execvpe` or telling the full path of the executable via `elf_aux_info`  are patched in a `LD_PRELOAD` library called `libpl_hack.so` in `preload_hack.c`.

## Development Please ;)
I could use help in these areas,I will probably get them done myself but if you want to make my day:

 1. Add a command line switch to toggle *root user* mode(spoofing)
 2. Add support for `riscv64` and `arm64` in `abi.c`.
 3. Make the tool extremely fun to use(have emojis and stuff)
