HTB Name
===

HTB Reversing Challenge

Place Achieved: #91

By DisplayGFX
___
Description
```
After complains from reverse engineers that the challenges are heavily straining their F5 keys and gdb-muscles, we put in the work to develop techniques to combat these symptoms.
```

There is only one file, `nopeeking`. It is a ELF binary, so lets get this into Ghidra.
## Initial Enumeration

It first starts with a `__libc_start_main`, which as always, means that the first parameter is the `main` function, and the other functions in the call are fallover functions, which can safely be labeled as `void` for reversing purposes.

Moving onto `main`, we see this
```c
undefined8 main(void)

{
  __pid_t _Var1;
  
  *(undefined2 *)PTR_DAT_00302118 = 0;
  DAT_00302160 = mmap(NULL,4,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
  DAT_00302168 = mmap(NULL,4,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
  DAT_00302170 = mmap(NULL,4,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
  DAT_00302150 = mmap(NULL,0x1b,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
  DAT_00302158 = mmap(NULL,4,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
  *DAT_00302160 = 0;
  *DAT_00302168 = 0;
  signal(SIGCHLD,SIG_IGN);
  prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY);
  _Var1 = fork();
  if (_Var1 == 0) {
    ptrace(PTRACE_TRACEME,0,0,0);
    otherID = getppid();
    _Var1 = getppid();
    ptrace-attach(_Var1);
    while (DAT_00302140 != 0) {
      FUN_00101463();
    }
  }
  else if (0 < _Var1) {
    FUN_00100cb8();
    while (DAT_00302140 != 0) {
      FUN_0010151c();
    }
    munmap(DAT_00302160,4);
    munmap(DAT_00302168,4);
    munmap(DAT_00302170,4);
    munmap(DAT_00302150,0x1b);
    munmap(DAT_00302150,4);
  }
  return 0;
}
```

First is the block at the beginning of `mmap`s, which in brief creates a memory space for data of a specified length (with the 2nd parameter) to be stored.

To identify what value means what, I used the manpage [here](https://man7.org/linux/man-pages/man2/mmap.2.html). To Identify the flags, I used the header file for `mmap` [here](https://codebrowser.dev/glibc/glibc/sysdeps/unix/sysv/linux/bits/mman-linux.h.html)

The only thing that changes between the calls is the length of the memory assigned. The rest remains all the same, and here is what each of the flags mean
- PROT_READ and PROT_WRITE - They mean that the mapped memory will be readable and writable
- MAP_SHARED - in the case that the program is duplicated or forked, the pointers will share this bit of memory assigned by `mmap`.
- MAP_ANONYMOUS - simply means that it will not use a file, and that the values in the memory are initialized to zero.

Theres then a call to signal, which simply (after decoding with signal headers, easiest done with ghidra's `E` instead of looking it up) sets a handler on getting `SIGCHLD` (when the child process is terminated) to ignore the signal to shut down. This will be important later.

Then, a call to `prctl` with a strange value `0x59616d61`. Googling this number will show its a special flag `PR_SET_PTRACER`. Which is a flag that allows a specific process to ptrace it. Following the manpage for [this flag](https://man7.org/linux/man-pages/man2/PR_SET_PTRACER.2const.html) (as prctl has pages for each flag) shows exactly what `-1` means in this context. It means `PR_SET_PTRACER_ANY`, which means there's no restrictions on what can ptrace the calling process.

Then there is a fork call, which splits the process into two processes. the parent process will see the child process id returned, while the child process will get a zero returned. So, to bifurcate the static process tracing, lets look at what the child and parent will do. The parent will call 2 functions. 
One to start, which if you investigate, will wait until a value (labeled as otherID), and a loop which will endlessly call another function. This is to be examined later.

Meanwhile, the child function will call `ptrace` to indicate the program is ready to be traced. Then, it will get its own `ppid`, and set it to `otherID`.  Then it calls a function, passing in its own `ppid`. 

### ptrace-attach
```c
void ptrace-attach(pid_t ppid)

{
  __pid_t _Var1;
  undefined local_14 [4];
  
  ptrace(PTRACE_ATTACH,ppid,0,0);
  wait-sig(local_14);
  ptrace(PTRACE_POKETEXT,ppid,&otherID,getpid());
  ptrace(PTRACE_CONT,ppid,0,0);
  return;
}
```

All this does is that it attaches to the parent, and implants its own `process id` into the parent.

So, this establishes that, in the parent and child process, each one has implanted a set shared memory addresses and the other's process id. Then both of them call a function for the parent and child process respectively.

## parent_func and child_func

```c

void child_proc(void){
  int iVar1;
  
  *child_running = 1;
  *turn3? = 1;
  FUN_00100cd5(otherID,1);
  while ((*parent_running != 0 && (*turn3? == 1))) {
    FUN_00100cd5(otherID,1);
    sleep.5sec();
    if (otherID == 0) {
      return;
    }
  }
  FUN_00100cd5(otherID,1);
  if ((error == 0) && (iVar1 = FUN_00100ff9(), iVar1 != 0)) {
    error = 1;
  }
  *child_running = 0;
  return;
}

void parent_func(void)

{
  int iVar1;
  
  *parent_running = 1;
  *turn3? = 0;
  FUN_00100cd5(otherID,1);
  while ((*child_running != 0 && (*turn3? == 0))) {
    FUN_00100cd5(otherID,1);
    sleep.5sec();
    if (otherID == 0) {
      return;
    }
  }
  FUN_00100cd5(otherID,1);
  if ((error == 0) && (iVar1 = FUN_00101221(), iVar1 != 0)) {
    error = 1;
    otherID = 0;
  }
  *parent_running = 0;
  return;
}
```

These two are very similar to each other. they set "their own" set of memory to be either true or false, presumably to designate that it is running, execute the same function, in a while loop, while this third memory value is going, and once either the `otherID` is nulled out, the shared memory region is zeroed out, or the third value is flipped (the first real difference between child and parent).

meanwhile, it calls this function `FUN_00100cd5`.

The only other real difference is that it calls another function `FUN_00101221` or `FUN_00100ff9`. If either of these functions return anything other than zero, its an error state.

Next step is to look at the common function: FUN_00100cd5
### Instruction Feeder

Here is the function after cleaning up with a bit of macros and variable names from from `sys/wait.h`, `sys/signal.h` and replacing variables with their names

```c
bool FUN_00100cd5(uint otherIDl,int anyWait)

{
  if (otherIDl == 0) {
    return false;
  }
  else {
    if (anyWait == 0) {
      wait(&wstatus);
    }
    else {
      local_124 = waitpid(otherIDl,&wstatus,WNOHANG);
      if (local_124 != otherIDl) {
        return true;
      }
    }
    if (WIFEXITED(wstatus)) {
      otherID = 0;
      return false;
    }
    else if (WIFSTOPPED(wstatus)) {
      stopReason = WSTOPSIG(wstatus);
      ptrace(PTRACE_GETREGS,(ulong)otherIDl,0,local_118);
      lVar2 = ptrace(PTRACE_PEEKTEXT,(ulong)otherIDl,local_98,0);
      local_11c = (uint)lVar2 >> 0x10;
	  if (stopReason == SIGILL) {
...
}

```

So, to explain the function a bit, the first part is setting up the program to wait on the other process. `wait` will wait for any child process to signal that its terminated (or stopped). `waitpid` specifically waits on the specified process until it hangs in this case. 

Then, thanks to the magic of macros, its easy to spot what the program is doing. The program should resume after the wait because the program stopped, paused, or halted somehow. In the case of `waitpid`, theres error checking to make sure it returns to the program correctly. 

Then it will check if it has exited. `WIFEXITED(x)` is a macro for `((x) & 0x7f) == 0`, and thus you can replace the code with the macro to make more sense of the code. I took the liberty of doing so with any macro and the associated code. If it is true, `otherID` is nulled out, and the program returns false (in this case, indicating good execution, or not for this path). Then, another macro, `WIFSTOPPED(x)` or `(((x) & 0xff) == 0x7f)`, checks if it has stopped, and gets the signal it stopped with in the macro `WSTOPSIG(x)` or `(int)(((unsigned)(x) >> 8) & 0xff)`. If the signal was a `SIGILL` (`4`), it will proceed.

However, theres an issue. There is a call to `ptrace(PTRACE_GETREGS,(ulong)otherIDl,0,local_118)`, and then the program makes little sense after that, pulling from values that shouldnt make sense. Whats going on? Well, if you look at the manpage for [`ptrace` at `PTRACE_GETREGS`](https://man7.org/linux/man-pages/man2/ptrace.2.html) , you can see that it places the "general-purpose registers" and refers to `sys/user.h` to the structure of them. To get the right format of registers in Ghidra, its not enough to import the header, as it will import the incorrect structure. You need to make your own header with the correct register structure extracted.

```c
struct user_regs_struct
{
  __extension__ unsigned long long int r15;
  __extension__ unsigned long long int r14;
  __extension__ unsigned long long int r13;
  __extension__ unsigned long long int r12;
  __extension__ unsigned long long int rbp;
  __extension__ unsigned long long int rbx;
  __extension__ unsigned long long int r11;
  __extension__ unsigned long long int r10;
  __extension__ unsigned long long int r9;
  __extension__ unsigned long long int r8;
  __extension__ unsigned long long int rax;
  __extension__ unsigned long long int rcx;
  __extension__ unsigned long long int rdx;
  __extension__ unsigned long long int rsi;
  __extension__ unsigned long long int rdi;
  __extension__ unsigned long long int orig_rax;
  __extension__ unsigned long long int rip;
  __extension__ unsigned long long int cs;
  __extension__ unsigned long long int eflags;
  __extension__ unsigned long long int rsp;
  __extension__ unsigned long long int ss;
  __extension__ unsigned long long int fs_base;
  __extension__ unsigned long long int gs_base;
  __extension__ unsigned long long int ds;
  __extension__ unsigned long long int es;
  __extension__ unsigned long long int fs;
  __extension__ unsigned long long int gs;
};
```

Here is the revised version of the code, starting from the `WSTOPSIG`

```c
	  stopReason = WSTOPSIG(wstatus);
      ptrace(PTRACE_GETREGS,(ulong)otherIDl,0,local_118);
      lVar2 = ptrace(PTRACE_PEEKTEXT,(ulong)otherIDl,local_118.rip,0);
      local_11c = (uint)lVar2 >> 0x10;
      if (stopReason == SIGILL) { 
        switch (local_11c){
          case 0x494e:
            local_118.rax = DAT_00302144;
            break;
          case 0x4543:
            local_118.rax = (((*curChar + -1) * 0x2c ^ (((uint)local_118.r8 & 0xff) - *curChar) + 0x1a) & 0xff);
            break;
          case 0x4743:
            local_118.rax = *(char *)(*curChar + userin);
            *curChar = *curChar + 1;
            break;
          case 0x4f55:
            ptrace(PTRACE_POKETEXT,(ulong)otherIDl,&DAT_00302144,local_118.r8);
            break;
          case 0x5253:
            *curChar = 0;
            printf("Flag: ");
            fgets(local_38,0x1c,stdin);
            for (i = 0; i < 0x1b; i = i + 1) {
              userin[i] = local_38[i];
            }
            break;
        }
        local_118.rip = local_118.rip + 4;
        ptrace(PTRACE_SETREGS,(ulong)otherIDl,0,local_118);
        ptrace(PTRACE_CONT,(ulong)otherIDl,0,0);
      }
      return true;
    }
    else {
      return false;
    }
```

So, it waits until the program encounters an illegal instruction, and reads bytes right after the instruction. Then, it does things according to the bytes it reads, and sets the registers of the other process and restarts it right after the illegal instruction.
- 0x5253 - It will take in the flag into a certain area of memory, lets call it userin. It also zeros out a certain value, lets call that curChar.
- 0x4743 - sets RAX to a pointer for the current character in the flag and then advances the counter by one.
- 0x494e - sets RAX of the other process to a value stored in this process
- 0x4543 - sets RAX of the other process to a complex manipulation of the counter, the counter minus 1, and whatever is in r8
- 0x4f55 - sets the other process' value storage to whatever was in R8 of that process
Seems like a bit of a small virtual machine. And this also seems like an instruction handler for the program.

Now that is understood, lets look at the last two remaining functions, `FUN_00101221` and `FUN_00100ff9`

## Child and Parent - Flag Checking

Here is what ghidra decompiles when you visit one of the functions

```c
undefined8 FUN_00100ff9(void)

{
  ushort uVar1;
  code *pcVar2;
  
  uVar1 = *(ushort *)PTR_DAT_00302118;
  if (uVar1 == 0xd4) {
    if (0x1a < *curChar) {
      puts("\n");
      if (DAT_00302180 != 0) {
        puts("The first half of the flag looks correct");
      }
                    /* WARNING: Does not return */
      pcVar2 = (code *)invalidInstructionException();
      (*pcVar2)();
    }
    if (*(int *)(&DAT_00302020 + (long)*curChar * 4) == 0) {
                    /* WARNING: Does not return */
      pcVar2 = (code *)invalidInstructionException();
      (*pcVar2)();
    }
    rand();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  if (uVar1 < 0xd5) {
    if (uVar1 == 0) {
      _DAT_00302184 = 0;
      DAT_00302180 = 1;
                    /* WARNING: Does not return */
      pcVar2 = (code *)invalidInstructionException();
      (*pcVar2)();
    }
  }
  else {
    if (uVar1 == 0xda) {
                    /* WARNING: Does not return */
      pcVar2 = (code *)invalidInstructionException();
      (*pcVar2)();
    }
    if (uVar1 == 0xe5) {
                    /* WARNING: Does not return */
      pcVar2 = (code *)invalidInstructionException();
      (*pcVar2)();
    }
  }
  return 2;
}
```

Its nonsense, because there are illegal instructions everywhere. However, if you look at the assembly, you can see its a simple `UD2`. 
```
...
0010105b 028   b8 00 00        MOV        EAX,0x0
			   00 00
00101060 028   41 89 c0        MOV        R8D,EAX
00101063 028   0f 0b           UD2
00101065       55              ??         55h    U
00101066       4f              ??         4Fh    O
00101067       0f              ??         0Fh
00101068       0b              ??         0Bh
```

And look, if you remember, you can spot the bytes that were matched up in the virtual machine earlier in the program! `55`, `4f`, that must take the r8 register, and store it somewhere in this program.

If you are following along, you need to delve into the assembly and look for a `UD2` symbol. Check the next 2 bytes, note them down, and change the `UD2` instruction to `NOP/reserved AX` with `Shift+Ctrl+G`. This is long enough to cover the `UD2` instruction and the following 2 bytes to be non-functional and invisible to the decompiler. dont forget to note down exactly what it is doing in comments (PROTIP: use `;` to set the comments on the first instruction in the conditional block, this should show up in the decompiled code)

After this arduous task, this is the code you will end up with something that makes a bit more sense. It looks something like this when reoriented...
```c
undefined8 FUN_00100ff9(void)

{
  ushort uVar1;
  code *pcVar2;
  bool bVar3;
  undefined8 uVar4;
  
  bVar3 = true;
  uVar1 = *(ushort *)PTR_DAT_00302118;
  switch (uVar1){
    case 0:
          /* Extra ops:
        DAT_00302144 = r8
        take userInput */
      _DAT_00302184 = 0;
      DAT_00302180 = 1;
      PTR_DAT_00302118 = 0xd4;
      return 0;
    case 0xd4:
      if (0x1a < *curChar){
        puts("\n");
        if (DAT_00302180 != 0) {
        puts("The first half of the flag looks correct");
        /* extraOp:
          DAT_00302144 = 0x100 (r8d) */
        }
        return 2;
      }
      if (INT_ARRAY_00302020[*curChar] != 0) {
        rax = rand() & 0xff;
      } else {
        /* Extra Op:
        rax = userin[*curChar] & 0xff
        *curChar++;
        */
      }
      r8 = rax;
      /* Extraop:
       rax = ((((*curChar + -1) * 44) ^ ((r8 & 0xff) - *curChar) + 26) & 0xff);
      */
      rax = rax & 0xff;
      rax = rax | 0x200;
      /* Extraop
        DAT_00302144 = rax;
      */
      PTR_DAT_00302118 = 0xda;
    case 0xda:
      /* Extraop
        rax = Opposite proc's DAT_00302144
      */
     if (rax & 0x200 != 0){
        return 0;
     }
      /* Extraop
        rax = Opposite proc's DAT_00302144
      */
      if ((rax & 0x100) == 0) {
          return 0;
      }
....
	 //A comparison is made between ((((*curChar + -1) * 44) ^ ((r8 & 0xff) - *curChar) + 26) & 0xff) and a value in an array at 003020e0
  }
```

This isn't a complete deconstruction, but its enough to make sense. And the other function is similarly constructed. It compares against a 32 long int array at `0x00302020`, and if the value in spot in the array correlating to the current character is 1, it will proceed, if its not, then it will generate a random number in place of the user input.

From that, it performs a complex operation on the given character, best characterized by the below python
```python
def wildfunction(input,index):
    input = input & 0xff
    sum5 = ((input - index + 26) ^ (index - 1) * 44) & 0xff
    return sum5
```

Then, it compares the result against an array at `0x003020e0` (`0x003020a0` for the other function) against the result of the above function. if they are equal, the program proceeds. If not, then the program marks it down as incorrect and eventually flips a flag to mark it as such. This process is easily bruteforced for each character. Below is the python to do so.

```python
print(f"{'Index':>5} | {'Char':>5} | {'Enc Char':>9} | {'Result':>7} | {'mask':>4} | {'Final XOR':>10}")


def wildfunction(input,index):
    input = input & 0xff
    retvalue = ((input - index + 26) ^ (index - 1) * 44) & 0xff
    return retvalue

parent_or_child = [snip]
enc_parent =    [snip]
enc_child =    [snip]
enc_child_index = 0
enc_parent_index = 0 
for index in range(1, 28):   
    mask = (index - 1) * 44 & 0xff    
    if parent_or_child[index-1]:
        encrypted_char = enc_child[enc_child_index]
        enc_child_index += 1
    else:
        encrypted_char = enc_parent[enc_parent_index]
        enc_parent_index += 1
    for char in range(0, 0xff):
        result = wildfunction(char,index)
        if result^encrypted_char & 0xff == 0:
        #    print(f"{index:>5} | {chr(char):>5} | {hex(encrypted_char):>9} | {hex(result):>7} | {hex(mask):>4} | {hex(result^encrypted_char):>10}")
           print(chr(char),end="")
```

And that gets the flag!

[https://labs.hackthebox.com/achievement/challenge/158887/312]
