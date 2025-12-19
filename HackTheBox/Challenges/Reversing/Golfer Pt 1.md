Golfer Pt 1
===

HTB Challenge

By DisplayGFX
___

## Initial Enumeration
Now, looking at the binary, we can see that entry will immediately jump to another function.

```
        0800004c e9 d6 00        JMP        FUN_08000127
                 00 00

```

So, looking at it in ghidra...

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined FUN_08000127()
             undefined         AL:1           <RETURN>
                             FUN_08000127                                    XREF[1]:     entry:0800004c(T), 
                                                                                          entry:0800004c(j)  
        08000127 30 c0           XOR        AL,AL
        08000129 fe c0           INC        AL
        0800012b b3 2a           MOV        BL,42
        0800012d cd 80           INT        0x80
```

Looking at the instruction `INT 0x80` we can see this does a system call based on variables set above that instruction. using this link from [google's chromium documentation](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32_bit) we can see that the first interrupt with `AL` set to `1` is to exit out the code.

For solving the challenge, we can simply patch out the first jump instruction, and then try to run the binary again. This can be done in ghidra by first using `Ctrl+Shift+G`, and replacing the 5 bytes of the jump instruction with `NOP`s. so it should look something like this.

```
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined entry()
                               Thunked-Function: FUN_08000127
             undefined         AL:1           <RETURN>
                             entry                                           XREF[2]:     Entry Point(*), 08000018(*)  
        0800004c 66 90           NOP
        0800004e 66 90           NOP
        08000050 90              NOP

```

Run the program again by saving the current state in ghidra, using the `O` key, and selecting the option to export to `Original File`. Run this modified binary, and it will print out the flag.

https://labs.hackthebox.com/achievement/challenge/158887/378

## Understanding the binary

However, if we want to see what the program is doing, we can go further with ghidra.

If we hit `D` on the unknown bytes after the jump to the exit, we can tell ghidra to reinterpret the bytes as code once again.

This leads to a whole mess of code, but this also leads to a new function being created.

```c

void FUN_0800012f(void)

{
  code *pcVar1;
  
  pcVar1 = (code *)swi(0x80);
  (*pcVar1)();
  return;
}
```

Its a mess of code in the decompile view, but we can read the assembly at its only 4 instructions.
```
08000132 b0 04           MOV        AL,4
08000134 cd 80           INT        0x80
08000136 c9              LEAVE
08000137 c3              RET
```

We can see theres a similar function call, however this time, `AL` is set to 4.

Referring back to our the chromium syscall guide for x86, we can see that `4` is a write call, and it uses `ebx`, `ecx` and `edx` for `fd`, `buf`,`count` respectively. 

Consulting the [man pages for the write call](https://man7.org/linux/man-pages/man2/write.2.html), we can see that...
> 
> SYNOPSIS
>        \#include <unistd.h>
> 
>        ssize_t write(int <u>fd</u>, const void <u>buf</u>\[.count\], size_t <u>count</u>);
> 
> DESCRIPTION
>        write() writes up to <u>count</u> bytes from the buffer starting at <u>buf</u> to the file referred to by the file descriptor <u>fd</u>.

The description lays it out pretty plainly, however, the function call doesnt contain any of the variables we are looking for. But if we look backwards to all of the function calls, we can see that there are inputs...
```
08000051 fe c3           INC        BL
08000053 fe c2           INC        DL
08000055 b9 0a 00        MOV        ECX,Elf32_Ehdr_08000000.e_ident_pad[1]
		 00 08
0800005a e8 d0 00        CALL       FUN_0800012f                                     undefined FUN_0800012f()
		 00 00

```

So we can see that, `BL` and `DL` which are aliases (for this purpose) of `EBX` and `EDX` are incremented, and then a pointer to.... somewhere in the header in the file.

We can change the function in the program to take the write registers as inputs with the appropriate type. Go to the function that was called, and right click it and select "Edit Function Signature". Make sure to select "syscall"  in the calling convention.

We know there are 3 inputs in the `write` syscall, so click the plus sign 3 times and double click the datatype entry for each one. Using the chromium doc as a guide, set the inputs appropriately. The first one (`BL` at the moment) to `uint`, the second (`CL`) to `char *`, and the third (`DL`) to `size_t`. 

Afterwards, the function should look similar to the `write` syscall itself, but if we check back to the `entry` function...
```c
void __regparm3 entry(undefined4 param_1,undefined4 param_2)

{
  code *pcVar1;
  size_t sVar2;
  undefined4 unaff_EBX;
  uint uVar3;
  
  uVar3 = CONCAT31((int3)((uint)unaff_EBX >> 8),(char)unaff_EBX + '\x01');
  sVar2 = CONCAT31((int3)((uint)param_2 >> 8),(char)param_2 + '\x01');
  FUN_0800012f(uVar3,(char *)(Elf32_Ehdr_08000000.e_ident_pad + 1),sVar2);
  FUN_0800012f(uVar3,(char *)&Elf32_Ehdr_08000000.e_ident_abiversion,sVar2);
  FUN_0800012f(uVar3,(char *)&Elf32_Ehdr_08000000.e_flags,sVar2);
  FUN_0800012f(uVar3,(char *)(Elf32_Ehdr_08000000.e_ident_pad + 5),sVar2);
  FUN_0800012f(uVar3,(char *)(Elf32_Ehdr_08000000.e_ident_pad + 3),sVar2);
  FUN_0800012f(uVar3,(char *)((int)&Elf32_Ehdr_08000000.e_shoff + 3),sVar2);
  FUN_0800012f(uVar3,(char *)Elf32_Ehdr_08000000.e_ident_pad,sVar2);
  FUN_0800012f(uVar3,(char *)((int)&Elf32_Ehdr_08000000.e_shoff + 1),sVar2);
  FUN_0800012f(uVar3,(char *)&Elf32_Ehdr_08000000.e_ident_version,sVar2);
  FUN_0800012f(uVar3,(char *)(Elf32_Ehdr_08000000.e_ident_pad + 4),sVar2);
  FUN_0800012f(uVar3,(char *)((int)&Elf32_Ehdr_08000000.e_shoff + 2),sVar2);
  FUN_0800012f(uVar3,(char *)((int)&Elf32_Ehdr_08000000.e_shoff + 1),sVar2);
  FUN_0800012f(uVar3,(char *)&Elf32_Ehdr_08000000.e_ident_data,sVar2);
  FUN_0800012f(uVar3,(char *)((int)&Elf32_Ehdr_08000000.e_shoff + 1),sVar2);
  FUN_0800012f(uVar3,(char *)&Elf32_Ehdr_08000000.e_shoff,sVar2);
  FUN_0800012f(uVar3,(char *)((int)&Elf32_Ehdr_08000000.e_shoff + 3),sVar2);
  FUN_0800012f(uVar3,(char *)(Elf32_Ehdr_08000000.e_ident_pad + 6),sVar2);
  FUN_0800012f(uVar3,(char *)&Elf32_Ehdr_08000000.e_ident_osabi,sVar2);
  FUN_0800012f(uVar3,(char *)((int)&Elf32_Ehdr_08000000.e_shoff + 2),sVar2);
  FUN_0800012f(uVar3,(char *)((int)&Elf32_Ehdr_08000000.e_flags + 1),sVar2);
  FUN_0800012f(uVar3,(char *)(Elf32_Ehdr_08000000.e_ident_pad + 2),sVar2);
  pcVar1 = (code *)swi(0x80);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x80);
  (*pcVar1)();
  return;
}
```

Woah, thats a lot more!

We can see that every time through the mess of the code, we are feeding in `1` for both `BL` and `DL` and thus `uVar3` and `sVar2` are both 1. Meaning, we are sending 1 byte to STDOUT (1). The only thing that is changing is `ECX`. In this case, it seems to be taking individual bytes from the ELF header. Because neither the program nor ghidra really use the header, it would be easier to clear the type information in the header. Go to the very top of the program, and hit the `C` key to clear the type information for the ELF header.

Refer back to the code, double click where it is pointing, and make the resultant datapoint into a 1 length string by highlighting just the byte where its located, hitting `T`, and typing in `string`. The code then looks WAY more readable...

```c
void __regparm3 entry(undefined4 param_1,undefined4 param_2)

{
  code *pcVar1;
  size_t sVar2;
  undefined4 unaff_EBX;
  uint uVar3;
  
  uVar3 = CONCAT31((int3)((uint)unaff_EBX >> 8),(char)unaff_EBX + '\x01');
  sVar2 = CONCAT31((int3)((uint)param_2 >> 8),(char)param_2 + '\x01');
  FUN_0800012f(uVar3,"H",sVar2);
  FUN_0800012f(uVar3,"T",sVar2);
  FUN_0800012f(uVar3,"B",sVar2);
  FUN_0800012f(uVar3,"{",sVar2);
  FUN_0800012f(uVar3,"y",sVar2);
  FUN_0800012f(uVar3,"0",sVar2);
  FUN_0800012f(uVar3,"U",sVar2);
  FUN_0800012f(uVar3,"_",sVar2);
  FUN_0800012f(uVar3,"4",sVar2);
  FUN_0800012f(uVar3,"R",sVar2);
  FUN_0800012f(uVar3,"3",sVar2);
  FUN_0800012f(uVar3,"_",sVar2);
  FUN_0800012f(uVar3,"a",sVar2);
  FUN_0800012f(uVar3,"_",sVar2);
  FUN_0800012f(uVar3,"g",sVar2);
  FUN_0800012f(uVar3,"0",sVar2);
  FUN_0800012f(uVar3,"l",sVar2);
  FUN_0800012f(uVar3,"f",sVar2);
  FUN_0800012f(uVar3,"3",sVar2);
  FUN_0800012f(uVar3,"r",sVar2);
  FUN_0800012f(uVar3,"}",sVar2);
  pcVar1 = (code *)swi(0x80);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x80);
  (*pcVar1)();
  return;
}
```

And that's the flag!

https://labs.hackthebox.com/achievement/challenge/158887/378

Oh, and if you are wondering how it doesn't crash at the end of the entry function? the entry function just keeps on executing instructions right into the exit function, which exits with an error code of `42`.
