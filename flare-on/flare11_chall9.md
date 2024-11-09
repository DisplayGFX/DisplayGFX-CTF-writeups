Flare-On 11 <br>By DisplayGFX <br>Challenge 9: 
===

 Challenge Description:
```
A good career for you would be a sort of cyber Indiana Jones. Imagine a lone figure, a digital explorer, ventures into the depths of the bit forest, a sprawling, tangled expanse of code and data. The air crackles with unseen energy, and the path ahead twists and turns like a serpent's coil. At the heart of this forest lies the serpent's sanctum, a fortress of encrypted secrets. Your mission is to infiltrate the sanctum, navigate its defenses, and retrieve the hidden flag. Sounds way cooler than sitting at your desk typing things nobody cares about into a keyboard.
```

This challenge is probably the hardest one of them all. It took me down multiple false roads, days and days of effort, having to set it down for 2 weeks, and lots of frustration. But, in the end, I learned the most out of this one. So lets begin.

So, in this binary, there is only one file, `serpentine.exe`.  Here is what happens when you run it
```
PS...> .\serpentine.exe
...\serpentine.exe <key>
PS...> .\serpentine.exe  helloworld
Invalid key length.
PS...> .\serpentine.exe  helloworldthisis32characters!!!!
Wrong key
```

So, clearly, its searching for a key. And will reject anything that has the wrong key length, and is not the right key.

Taking a look at it in ghidra will reveal a lot, but the first stop is to take a look at the main function at `1400015b0` (you can find this by looking at functions in `__scrt_common_main_seh`)

```c
int main(int param_1,char **param_2){
  char *_Str;
  int iVar1;
  size_t sVar2;
  
  SetUnhandledExceptionFilter(FUN_140001180);
  if (param_1 == 2) {
    _Str = param_2[1];
    sVar2 = strlen(_Str);
    if (sVar2 == 32) {
      strcopy(userIn,_Str);
      (*(code *)PTR_14089b8e0)(userIn);
      iVar1 = 0;
    }
    else {
      printfWeird("Invalid key length.");
      iVar1 = 1;
    }
  }
  else {
    printf("%s <key>\n",*param_2);
    iVar1 = 1;
  }
  return iVar1;
}
```

There is the handling of the two outputs we encountered earlier, showing the usage, and stopping execution if the key isn't long enough.

But there's two points of interest. One is the execution of  what appears to be a pointer, that odd. The second is the usage of `SetUnhandledExceptionFilter` and the function it points to.

To clear the air, this will be used later, but this function just prints out that it didn't handle exceptions. This is a windows specific function, and will be called if no other exception handles an error.

```c
long exceptionHandler(_EXCEPTION_POINTERS *param_1){
  long lVar1;
  
  printfWeird????("Unexpected exception occurred.");
  lVar1 = exitFunc?(1);
  return lVar1;
}
```

But this pointer is not established in the code, so what could it be? Well to answer that question, you need only look at `tls_callback_0`. `tls_callback` functions will execute before any program call will in windows: [source](https://medium.com/@andreabocchetti88/tls-callbacks-to-bypass-debuggers-60409195ed76). So before the code jumps to wherever the pointer leads, its somehow established below.

```c
void tls_callback_0(undefined8 param_1,int reason)

{
  BOOL BVar1;
  
  if (reason == DLL_PROCESS_ATTACH) {
    PTR_14089b8e0 = VirtualAlloc((LPVOID)0x0,0x800000,0x3000,0x40);
    if (PTR_14089b8e0 == (LPVOID)0x0) {
      printfWeird????("Unable to allocate memory.");
      exitFunc?(1);
    }
    memNcpy(PTR_14089b8e0,&DAT_140097af0,0x800000);
  }
  else if (reason == DLL_PROCESS_DETACH) {
    BVar1 = VirtualFree(PTR_14089b8e0,0,0x8000);
    if (BVar1 == 0) {
      printfWeird????("Unable to free memory.");
      exitFunc?(1);
    }
  }
  return;
}
```

Some of the functions, like `memNcpy` are both inscrutable, and mind-numbingly dull to decipher. So, for the sake of time, I am skipping over those and just labeling them.

Here we see memory allocated to the pointer (with execution permission), and then memory copied to the virtual memory space allocated by the pointer. `0x800000` to be exact.

However, there are a few very easy to miss functions that are also called. Before `main` is called, there's an array of pointer to functions that run, starting at `1400172a8`. The ones I think are important start at `1400172a8`, labeled as `c_unkX`

```c
void c_unk1(void)

{
  c_unk1_unk(&DAT_1408a3310);
  return;
}
void * c_unk1_unk(void *param_1)

{
  longlong pdb;
  longlong lVar1;
  undefined *puVar2;
  
  puVar2 = param_1;
  //zeros out space
  for (lVar1 = 0x2a08; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  TEB = c_getTEB(); // returns TEB pointer
  *(param_1 + 0x2a08) = *(**(*(*(TEB + 0x60) + 0x18) + 0x20) + 0x20);
  return param_1;
}
```

theres a line in `c_unk1_unk` that dereferences a lot of times. We can follow along using `WinDBG`. Load in a x64 executable, any will do, and use the command `dt`. And then, just follow down the types.
```
1:001> dt _TEB
ntdll!_TEB
...
   +0x060 ProcessEnvironmentBlock : Ptr64 _PEB
1:001> dt _PEB
ntdll!_PEB
...
   +0x018 Ldr              : Ptr64 _PEB_LDR_DATA
1:001> dt _PEB_LDR_DATA
ntdll!_PEB_LDR_DATA
...
   +0x020 InMemoryOrderModuleList : _LIST_ENTRY
```

And then, there's another dereference that goes out of the bounds of a `_LIST_ENTRY`. According to the [microsoft article on the topic](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data), the structure for a list entry is actually

```
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

So this is where the entry lands.

```c
void c_unk2(void){
  longlong lVar1;
  undefined *puVar2;
  undefined local_18 [16];
  
  puVar2 = local_18;
                    /* clears out the stack */
  for (lVar1 = 1; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  INT_1408a3304 = c_unk2_unk(local_18);
  return;
}


undefined8 c_unk2_unk(void)

{
  longlong lVar1;
  char *pcVar2;
  uint local_68;
  
  lVar1 = InMemoryOrderModuleList +
          (ulonglong)
          *(uint *)(InMemoryOrderModuleList + *(int *)(InMemoryOrderModuleList + 0x3c) + 0x88);
  local_68 = 0;
  while( true ) {
    if (*(uint *)(lVar1 + 0x14) <= local_68) {
      return 0;
    }
    pcVar2 = (char *)(InMemoryOrderModuleList +
                     (ulonglong)
                     *(uint *)(InMemoryOrderModuleList + (ulonglong)*(uint *)(lVar1 + 0x20) +
                              (ulonglong)local_68 * 4));
    if ((((*pcVar2 == 'R') && (pcVar2[3] == 'I')) && (pcVar2[10] == 'F')) &&
       ((pcVar2[18] == 'T' && (pcVar2[23] == 'C')))) break;
    local_68 = local_68 + 1;
  }
  PTR_1408a32f8 =
       (undefined *)
       (InMemoryOrderModuleList +
       (ulonglong)
       *(uint *)(InMemoryOrderModuleList + (ulonglong)*(uint *)(lVar1 + 0x1c) +
                (ulonglong)
                *(ushort *)
                 (InMemoryOrderModuleList + (ulonglong)*(uint *)(lVar1 + 0x24) +
                 (ulonglong)local_68 * 2) * 4));
  return 0;
}
```

While I cannot explain what exactly the dereferencing is doing here, I have looked at the debugging while in this segment of the program, and that it IS looking for a specific function. its comparing function names against these specific characters. if you do a targeted enough search, you will come up with only one function name that matches: `RtlInstallFunctionTableCallback`. This will be important soon. But the last thing to know is the function pointer is exctracted, and stored within the program.

In ghidra, you can set data types to be exact function pointers, so setting that particular pointer to be `RtlInstallFunctionTableCallback` will allow for ghidra to interpret the future function calls correctly. for instance...
```c
void c_unk3(void){
  undefined8 uVar1;
  longlong lVar2;
  undefined *puVar3;
  undefined local_18 [16];
  //clears out memory
  puVar3 = local_18;
  for (lVar2 = 1; lVar2 != 0; lVar2 = lVar2 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  uVar1 = c_unk3_unk(local_18);
  INT_1408a3300 = (int)uVar1;
  return;
}


undefined8 c_unk3_unk(undefined *param_1){
  if (ptr_RtlInstallFunctionTableCallback != NULL) {
    (*ptr_RtlInstallFunctionTableCallback)
              ((ulonglong)main_ptr | 3,(DWORD64)main_ptr,0x2e4d26,
               FUN_1400245b0,(PVOID)0x0,(PCWSTR)0x0);
  }
  return 0;
}
```

This is where [`RtlInstallFunctionTableCallback`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlinstallfunctiontablecallback) is called. Looking at the article, `main_ptr` (where we previously found data loaded into a section of heap) is being set as a section of executable code, and an exception handler for that section is being set at `FUN_1400245b0`. We can also see the length of the executable code `0x2e4d26`.



Lets finally look at this exception handler function.

```c
int * FUN_1400010b0(longlong param_1){
  int *returnObj;
  uint oddBit;
  
  returnObj = (int *)operator_new(0xc);
  *returnObj = (int)param_1 - (int)DAT_14089b8e0;
  returnObj[1] = *returnObj + 1;
  returnObj[2] = returnObj[1] + 1 + (uint)*(byte *)(param_1 + 1);
  oddBit = (uint)((returnObj[2] & 1U) != 0);
  returnObj[2] = returnObj[2] + oddBit;
  return returnObj;
}
```

Referring back to the `Rtl...` function refered to earlier, heres what it has to say about this function.

>`[in] Callback`
>A pointer to the callback function that is called to retrieve the function table entries for the functions in the specified region of memory.
>...
>Function tables are used on 64-bit Windows to determine how to unwind or walk the stack. These tables are usually generated by the compiler and stored as part of the image. However, applications must provide the function table for dynamically generated code. For more information about function tables, see the architecture guide for your system.

So this gets a pointer, of some sort, and its used to create a relative number compared to the base of the heap address generated earlier in the program. Here's the structure of the returned object
- Relative pointer to.... somewhere in the program
- the same pointer, but 1 further
- A relative offset to the relative offset achieved earlier, but with bytes righter after the pointer given to the function.

To really understand, you need to reference these two articles
- [The microsoft article on x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)
- [and another article that covers unwind codes, X64 Deep Dive.](https://codemachine.com/articles/x64_deep_dive.html) (skip to the header `UNWIND_INFO and UNWIND_CODE`)
In the x64 Deep Dive article
> The BeginAddress and EndAddress fields of the RUNTIME_FUNCTION structure contain the offset of the start and end of the function's code in the virtual memory respectively, from the start of the module. When the function generates an exception, the OS scans the memory mapped copy of the PE file looking for a RUNTIME_FUNCTION structure whose extents include the current instruction address. **The UnwindData field of the RUNTIME_FUNCTION structure contains the offset of another structure that tells the OS runtime as to how it should go about unwinding the stack, this is the UNWIND_INFO structure**

So the structure must really be
- BeginAddress: the pointer, made to be a relative offset
- EndAddress: the same relative offset plus 1
- UnwindData: the same offset as EndAddress, but with the byte right after the pointer given as an additional offset.
And according to the two articles, this function is only called when there's an exception. So the pointer must be one to where the exception happened. To understand what actually happens, next lets turn our attention to the block of memory loaded into the heap. Here is the assembly view, starting from the first byte called as if it was code.
```
06000000       f4              HLT
06000001       46              ??         46h    F
06000002       54              ??         54h    T
06000003       3c              ??         3Ch    <
...
```

From what we know, the byte `0x46` is used as a relative offset. and if we cast whatever is 0x46+1+1 down the program as an `UNWIND_INFO`... (the structure is defined in the microsoft article, which can be different from ghidra, adjust appropriately)
```
				 unwind0
		  06000048       09 00 00        UNWIND_I
						 00 98 00 
						 00 00
06000048 09              uchar:3   01h                     Version
06000048 09              uchar:5   01h                     Flags
06000049 00              uchar     00h                     SizeOfProlog
0600004a 00 00           uchar     00h                     CountOfCodes
0600004c 98 00 00 00     int       98h                     retAddr
```

This was relatively sane, and its a good sign that the 4 byte int turns out to be an offset relatively close towards where it was called. If we check this offset relative to the block, we can see that its executable code that is not using exotic instructions, another good sign.
```
06000098       e8 8a 4c        CALL       x_func1
			   2e 00
0600009d       7f              ??         7Fh    
```

And then, following execution to this function call, we see almost a pattern.

```
	 **************************************************************
	 *                          FUNCTION                          *
	 **************************************************************
		 undefined x_func1()
	undefined         AL:1           <RETURN>
 
062e4d27       8f 05 33        POP        qword ptr [LAB_062e4d5e+2]
		       00 00 00
062e4d2d  -8   50              PUSH       RAX
062e4d2e   0   48 c7 c0        MOV        RAX,0x0
			   00 00 00 00
062e4d35   0   8a 25 eb        MOV        AH,byte ptr [DAT_062e4d26]
			   ff ff ff
062e4d3b   0   67 8d 80        LEA        EAX,[EAX + 0x7f497049]
			   49 70 49 7f
062e4d42   0   89 05 01        MOV        dword ptr [DAT_062e4d49],EAX
			   00 00 00
062e4d48   0   58              POP        RAX
062e4d49       49              ??         49h    I
062e4d4a       bb              ??         BBh
062e4d4b       49              ??         49h    I
062e4d4c       bb              ??         BBh
062e4d4d       dd              ??         DDh
062e4d4e       0a              ??         0Ah
062e4d4f       01              ??         01h
062e4d50       00              ??         00h
062e4d51       00              ??         00h
062e4d52       00              ??         00h
062e4d53 - ? - c7 05 ec        MOV        dword ptr [DAT_062e4d49],0x676742dd 
			   ff ff ff 
			   dd 42 67 67
062e4d5d - ? - 50              PUSH       RAX  
062e4d5e - ? - 48 b8 9d        MOV        RAX,0x9d
			   00 00 00 
			   00 00 00 00
062e4d68 - ? - 48 8d 40 05     LEA        RAX,[RAX + 0x5]
062e4d6c - ? - 48 87 04 24     XCHG       qword ptr [RSP]=>local_res0,RAX
062e4d70 - ? - c3              RET
```

This code will take the return address, push it to the stack, and use the register to load a byte, and modify its own code to load an instruction, then erase that instruction again.

Then, it takes the return value, adds 0x5 to it, exchanges it with the top of the stack to preserve the RAX it comes in with, and returns.

If you jump ahead 5 bytes...

```
  060000a2       41 53           PUSH       R11
  060000a4       68 36 54        PUSH       0x73775436
				 77 73
  060000a9       68 43 4c        PUSH       0x68a04c43
				 a0 68
  060000ae       68 f9 7f        PUSH       0x12917ff9
				 91 12
  060000b3       e8 de 4c        CALL       x_func2
				 2e 00
```

Another bunch of sane instructions, another call. And a similar pattern repeats. This is enough of a pattern to automate!

My python script that automates the disassembly of the (real) instructions is in the surrounding files, named `flare11_chall9_disasm1.py`. Its much too long to go into detail, but it covers the patterns discovered above, and also implements `UNWIND_CODE`s to some extent. 

### Unwind codes

While my solution didn't bother with unwind codes that much, I did do extensive research into them. Unfortunately, I was not able to emulate them effectively. Nor do I feel confident enough in my knowledge of how the operation of each unwind code work to cover them here. I will provide some of the original files towards the end of this writeup.

However, generally speaking, unwind codes are used as a way of undoing operations. The unwind codes usually represent what the function is doing in terms of the stack and registers. For instance `SAVE_NONVOL_REG` will save a register to the stack. So, the unwind code tells the OS to undo this operation by popping the value from the top of the stack onto the register. Thus undoing what the "instruction" did. However, with this challenge, there is no instruction to undo, and the creators are using it like a small virtual machine. Even then, I had spent hours and hours learning and trying to reimplement in a visible way this operation and failed. Here be dragons if you wish to do the same. That said, most of the operations are easy to understand if taken to be "opposite day" versions of what you expect.

However, when needed, I will explain what I believe the unwind codes do.
## Context frames

Whenever an exception happens, all of the registers are stored away, and kept for processing by the unwind codes. When Windows returns control back to the program, per the unwind code, a bunch of the registers are changed and none of the original registers are kept in the program. The one that we and this program are concerned about is `r9`. This is where the context dispatcher lives. This has a complete context of what the CPU was doing, including registers, at the time of the exception.

However, the important part is that this is ***after*** the unwind codes are executed upon the registers.

Here is an example from the first exception that has unwind codes

```
0x2e4d49: 	movabs r11, 0x14089b8e8
0x    a2: 	push r11
0x    a4: 	push 0x73775436
0x    a9: 	push 0x68a04c43
0x    ae: 	push 0x12917ff9
0x2e4e21: 	jmp 0x107
hlt at 0x107
UWOP_PUSH_3X
UWOP_ALLOC_LARGE 3 bytes 0x4
UWOP_PUSH_NONVOL r13
0x   1a7: 	mov rbp, qword ptr [r9 + 0x28]
0x2e4e8c: 	mov rdi, qword ptr [rbp + 0xe0]
0x   1b2: 	movzx rdi, dil
```

For simplicity's sake, I have simplified a few of the instructions and opcodes.

Here we have a pointer to the program, this time its pointing to the user input. Then 3 other values which have no effect aside from being filler bytes. Then, the program jumps to a `hlt`, which causes an exception, which is handled. I have printed the exceptions here. Remember, we undo each action according to the unwind code. 

So, first one pushes 3 values, so we pop them, discarding the irrelevant values. Then, theres an `UWOP_ALLOC_LARGE`, which verified experimentally, will add the value (`0x4`) to a pointer at the top of the stack, and dereference it by getting the values within. Then lastly is a `UWOP_PUSH_NONVOL`, which will undo a push, or in other words, pop to `r13`. These are all done to registers effectively before the `hlt`. In other words, these operations will get characters from the user input starting with the 4th character.

So why the big deal about registers being manipulated when they are all discarded in the end? Well, that's because they are actually stored in the `DispatcherContext`. More specifically in the 
`ContextRecord`.  While briefly touched upon in the exception handling page, a [`context`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context) contains all of the registers and all of the CPU context you would need from the state before the exception. But after the unwind codes.

This is what is happening with `qword ptr [r9 + 0x28]`. This gets the context record. And this line `[rbp + 0xe0]` is getting register `r13` from the context object, which is the user input starting with the 4th character. And then the next instruction will isolate the 4th character with a `movzx`. Neat!



Regardless, there is now a list of effective instructions... and its **131429** lines long, 3.2 **Megabytes**!  That is much much too large to effectively analyze it by hand. Instead, we must analyze it with python scripts that treat the output as the source itself.

## My solution: Pattern recognition

So, to compensate for the obscene amount of lines and megabytes needed to be analyzed, it will be much much easier to analyze the patterns of the effective assembly. Now, to do this, you need to recognize patterns and replace where constant first, and follow exact execution second (or not always). I couldn't tell you *exactly* how this works. however, I can tell you how 90% of it works, and that's good enough to solve this challenge.

### First pattern: pointers to program

```
0x2e4d49: 	movabs r11, 0x10add7f49
0x    a2: 	push r11
0x    a4: 	push 0x73775436
0x    a9: 	push 0x68a04c43
0x    ae: 	push 0x12917ff9
0x2e4db8: 	add qword ptr [rsp + 0x18], 0x35ac399f
```
A push to the top of the stack wth `movabs`, and an `add` to this number. There are also 3 separate values, and as far as I can tell, they serve no purpose. One wonders what the data could be. But if you add these two numbers up, they consistently point into the program.

As a sidenote, if you run `checksec-py` on the file, you will find there is no ASLR.

Lets collapse this block into just one, and remove the superfluous instructions.

```
0x2e4d49: 	whitebox 0x14089b8e8
0x2e4e21: 	jmp 0x107
hlt at 0x107
```
Not perfect, but better.

Another pattern is to recognize the only other usage of `movabs` is to add 2 numbers together to get a greater value.
```
0x2e54ae: 	movabs r14, 0xd4431f4b
0x2e5519: 	add r14, 0x6bc64375
```

Lets add these values together and get
```
0x2e5440: 	ldmxcsr dword ptr [r15 + 0x90]
0x2e54ae: 	whitebox 0x1400962c0
0x2e5585: 	mov r14, qword ptr [r14 + 0x468]
```
Losing a register, sure, but gaining an insight.

Next is to view what pointers that whitebox is pointing to. Easily done in two ways, gather and analyze the pointers made. or, my favorite, create a switch case that errors out, until you have one that does not error out.

```python
import re

def deblackbox(val:int):
    match val:
        case 0x1400942c0:
            box_str = 'pointer 1'
        case 0x140094ac0:
            box_str = 'pointer 2'
        case 0x1400952c0:
            box_str = 'pointer 3'
        case 0x140095ac0:
            box_str = 'pointer 4'
        case 0x1400962c0:
            box_str = 'pointer 5'
        case 0x140096ac0:
            box_str = 'pointer 6'
        case 0x1400972c0:
            box_str = 'pointer 7'
        case 0x14089b8e8:
            box_str = 'pointer 8'
        case 0x1400011f0:
            box_str = 'pointer 9'
        case _:
            box_str = hex(val)
            raise NotImplementedError
    return box_str

# Function to handle the replacement
def replace_movabs_add(match):
    movabs_value = int(match.group(1), 16)
    add_value = int(match.group(2), 16)
    
    total_value = movabs_value + add_value
    box_str = deblackbox(total_value)
    return f'whitebox {box_str}'

def replace_pushstack(match):
    movabs_value = int(match.group(1), 16)
    add_value = int(match.group(2), 16)
    
    total_value = movabs_value + add_value
    box_str = deblackbox(total_value)
    return f'whitebox {box_str}'

with open('instr.txt',"r") as x:
    text = x.read()

movabs_add_pattern = r'\bmovabs\s+\w+,\s+(0x[0-9a-fA-F]+)\b\n0x[0-9a-fA-F]+:\s+add\s+\w+,\s+(0x[0-9a-fA-F]+)\b'
pushstack_pattern = r'\bmovabs\s+\w+,\s+(0x[0-9a-fA-F]+)\b\n(?:.*push.*\n)*0x[0-9a-fA-F]+: \tadd qword ptr \[rsp \+ 0x[0-9a-fA-F]+\], (0x[0-9a-fA-F]+)'

result = re.sub(movabs_add_pattern, replace_movabs_add, text)
result = re.sub(pushstack_pattern, replace_pushstack,result)

print(result)
```

This does all of the above. But these pointers. What do they do?

- `0x1400011f0` points to the `Wrong Flag` functon. 
- `0x14089b8e8` points to the user input for the flag.
But that still leaves 7 pointers remaining

So, following each of the 7 pointers will lead you to.... more pointers, an array of pointers for each one, each 8 bytes long.

Lets look at how its used.

```
0x377a84: 	whitebox pointer 1; (pushed to the top of the stack)
0x377b5f: 	jmp 0x5bec6
hlt at 0x5bec6
			FP register used at r13
UWOP_SET_FPREG rax
UWOP_ALLOC_LARGE 2 bytes 0xff; multiplied by 8, to account for pointers
UWOP_PUSH_NONVOL rax
0x 5bf60: 	mov r14, qword ptr [r9 + 0x28]; context record
0x 5bf64: 	ldmxcsr dword ptr [r14 + 0x34]; mxcsr from exception
0x 5bf69: 	mov r15, qword ptr [r14 + 0x78]; RAX from exception
0x377bc9: 	mov r12, qword ptr [r14 + 0x90]; RBX from exception
0x377c31: 	jmp 0x5bfbc
hlt at 0x5bfbc
Empty unwind
0x 5c052: 	mov r12, qword ptr [r9 + 0x28]; context record
0x377c94: 	mov r15, qword ptr [r12 + 0xd8]; r12 from exception
0x 5c05e: 	mov ecx, dword ptr [r12 + 0x34]; mxcsr from exception
0x377cfc: 	add rcx, qword ptr [r12 + 0xf0]; r15 from exception (dereferenced pointer1) added to rcx (mxcsr)
0x 5c06b: 	mov r8b, byte ptr [rcx]; pointer to this is dereferenced, and byte extracted
```

Here we see that `pointer 1` is dereferenced after having `0xff` added to it, mxcsr is added to this, and a byte is extracted.

If you look for wherever these 7 pointers are used, you will see a similar pattern as such:
- pointer is dereferenced, after having a byte ranging from 0x00 to 0xff added to it, resulting in a pointer
- to this pointer, some single byte is added to the value
- the resultant pointer is then dereferenced for a single byte to be extracted.
In other words, the behavior is very similar to a 2d array. Of size 256 by 256.

So, lets take a few views of pointer 1, by looking at what each array looks like if we assume this 2d array. It will be easy to spot a trend if we look at a list of values when accessing the first dimension of the 2d array.

`pointer 1`\[0\]
```
140898670       00              ??         00h
140898671       00              ??         00h
140898672       00              ??         00h
140898673       00              ??         00h
...
```

`pointer 1`\[0xff\]
```
140093bc0       00              ??         00h
140093bc1       01              ??         01h
140093bc2       02              ??         02h
140093bc3       03              ??         03h
140093bc4       04              ??         04h
...
140093cbc       fc              ??         FCh
140093cbd       fd              ??         FDh
140093cbe       fe              ??         FEh
140093cbf       ff              ??         FFh
```

`pointer 1`\[0xaa\] (1010 1010 in binary)
```
14006e8c0       00              ??         00h
14006e8c1       00              ??         00h
14006e8c2       02              ??         02h
14006e8c3       02              ??         02h
14006e8c4       00              ??         00h
14006e8c5       00              ??         00h
14006e8c6       02              ??         02h
14006e8c7       02              ??         02h
14006e8c8       08              ??         08h
14006e8c9       08              ??         08h
...
14006e9b9       a8              ??         A8h
14006e9ba       aa              ??         AAh
14006e9bb       aa              ??         AAh
14006e9bc       a8              ??         A8h
14006e9bd       a8              ??         A8h
14006e9be       aa              ??         AAh
14006e9bf       aa              ??         AAh
```

With these values..... this looks like an AND operation between the X and Y of the values in the array. And it is, confirmed if you wish to look at more and more values.

This pattern holds true across all 7 pointers.
- pointer 0x1400942c0 : 'x_AND_y'
- pointer 0x140094ac0 : 'x_XOR_y'
- pointer 0x1400952c0 : 'x_OR_y'
- pointer 0x140095ac0 : 'x+y_AND_0xff'
- pointer 0x140096ac0 : 'y_minus_x'
These two pointer are a bit special, as they all will be `0` or `1`, based on the values described below.
- pointer 0x1400972c0 : 'x_greater_then_y_bitset'
- pointer 0x1400962c0 : '255-x_greater_than_y_bitset'

That's the pointers named, and understood.

### Second pattern: `test r14,r14`

```
0x30a2d7: 	whitebox wrong_flag
0x 179fd: 	test r14, r14
0x30a3af: 	lea r12, [rip - 0x2f29a8]
0x 17a07: 	cmovne r12, r15
0x 17a0b: 	jmp r12
```

If you look for conditional execution in the program, you will only find the instruction `cmovne`. There are 32 incidents of this (31 in my program), and every single one is identical in pattern to this one. It will load in the pointer to the wrong flag function, test a register to see if it is zero, load the pointer to resume normal execution, and conditionally move the wrong flag function pointer into a register if the test failed, and jump to that pointer. either to the wrong flag function if `r14` in this case is not zero, or the normal execution if it is zero.

In other words, there are 32 checks for the program. Important info for later. But also important to note that whatever the checks do to get to this register will at least be greater than 32, if not a multiple of 32.

### Third pattern: `mul qword ptr [rsp]`

```
0x2e4d49: 	whitebox in_flag
...
UWOP_ALLOC_LARGE 3 bytes 0x4
UWOP_PUSH_NONVOL r13
0x   1a7: 	mov rbp, qword ptr [r9 + 0x28]
0x2e4e8c: 	mov rdi, qword ptr [rbp + 0xe0]
0x   1b2: 	movzx rdi, dil
...; inflag[4] is moved to RAX
0x2e4fc3: 	mov r10, 0xffffffffb93774a7
0x2e502f: 	add r10, 0x47b805e5
0x   2bb: 	push r10
0x   2bd: 	mul qword ptr [rsp]
```
If you search for `mul qword ptr [rsp]`, there are 256 (8\*32) occurrences of this line, and for each and every single one, you will always find `in_flag` preceeding this line. 

For each one, the program will extract a single character, and then do a weird dance of values where it adds `0x47b805e5` and `0xffffffffb93774a7`. This causes an overflow, so the resultant value is actually `0xEF7A8C`. Then, it multiplies this character by this value. This is such a constant, you can make a regex pattern out of it.

```python
import re

with open("whiteinst.txt","r") as x:
    data = x.read()

lines = data.splitlines()
results = []

for i, line in enumerate(lines):
    if 'mul qword ptr [rsp]' in line:
        mov_value = None
        add_value = None

        for j in range(i-1, max(i-10,0), -1):
            if 'add' in lines[j] and add_value is None:
                add_match = re.search(r'add [^,]+, (0x[0-9a-fA-F]+)', lines[j])
                if add_match:
                    add_value = int(add_match.group(1), 16)
            if 'mov' in lines[j] and mov_value is None:
                mov_match = re.search(r'mov [^,]+, (0x[0-9a-fA-F]+)', lines[j])
                if mov_match:
                    mov_value = int(mov_match.group(1), 16)
            if mov_value is not None and add_value is not None:
                break

        for k in range(i, max(i-30, 0), -1):
            if 'UWOP_ALLOC_LARGE' in lines[k]:
                uwop_match = re.search(r'UWOP_ALLOC_LARGE . bytes (0x[0-9a-fA-F]+)', lines[k])
                if uwop_match:
                    uwop_alloc_value = int(uwop_match.group(1), 16)
                break
            elif 'UWOP_ALLOC_SMALL' in lines[k]:
                uwop_match = re.search(r'UWOP_ALLOC_SMALL (0x[0-9a-fA-F]+)', lines[k])
                if uwop_match:
                    uwop_alloc_value = int(uwop_match.group(1), 16)
                break


        if mov_value is not None and add_value is not None:
            result = {
                'char' :  uwop_alloc_value,
                'mov + add': hex((mov_value + add_value)&0xffffffffff)
            }
            results.append(result)


for idx, result in enumerate(results):
    print(f"userflag[{result['char']:02d}] * {result['mov + add']}")
```

```
userflag[04] * 0xef7a8c
userflag[24] * 0x45b53c
userflag[24] * 0xe4cf8b
userflag[08] * 0xf5c990
userflag[20] * 0x733178
userflag[16] * 0x9a17b8
userflag[12] * 0x773850
userflag[28] * 0xe21d3d
test
```

If it was a simple multiplication, then it would be trivial to give the flag as all `00` values to succeed. That is not the case here.

However, this does give a pattern for anchoring every pattern afterwards off of.

But, how do we know how these values are handled? As the first example of anchoring off of the `mul` command, if we look at the 7th line after there will always be either a `push`, `add`, `sub` or an `xor` instruction. So each grouping of checks looks something like the below

```
sum += userflag[04] * 0xef7a8c
sum -= userflag[24] * 0x45b53c
sum -= userflag[24] * 0xe4cf8b
sum -= userflag[08] * 0xf5c990
sum ^= userflag[20] * 0x733178
sum ^= userflag[16] * 0x9a17b8
sum ^= userflag[12] * 0x773850
sum ^= userflag[28] * 0xe21d3d
test
```

and below is the code added to grab this information.
```python
opline = lines[i+7]
print(opline)
opmatch = re.search(r'0x[0-9a-fA-F\ ]+: \t\b([A-Za-z]+)\b',opline)
opcodeline = opmatch.group(1)
match opcodeline:
	case "sub":
		opcodeline = '-'
	case "xor":
		opcodeline = '^'
	case "add" | "push":
		opcodeline = '+'
```

Even now, if you follow along via debugging, this does not fully predict what the values at the end of each test. Onward.

### Fourth Pattern: `shl` and 2d array pointers

Continuing on the theme of anchoring off of `mul qword ptr [rsp]`, if you observe what happens to the value afterwards, you will see that one instruction will pop up again and again, surrounded by pointers to 2d arrays, `shl` followed by a register and a multiple of `0x8`.

```
0x   2bd: 	mul qword ptr [rsp]
...
0x2e54ae: 	whitebox 255-x_greater_than_y_bitset
0x2e5585: 	mov r14, qword ptr [r14 + 0x468]
0x2e55ef: 	add r14, previous rbx
0x   6bc: 	mov sil, byte ptr [r14]
0x   6bf: 	movzx rsi, sil
0x   6c3: 	shl rsi, 8
0x2e565a: 	add qword ptr [r15 + 0xf0], rsi
0x   6ce: 	ContextRecord to rax
0x2e56c3: 	moving previous r15 into r13
0x2e572c: 	whitebox x+y_AND_0xff
hlt at 0x737
			FP register used at rbx
UWOP_SET_FPREG rax
UWOP_ALLOC_LARGE 2 bytes 0x8d; 
UWOP_PUSH_NONVOL r15
0x   7de: 	ContextRecord to rdx
0x   7e2: 	moving previous MxCsr into mxcsr
0x2e5865: 	moving previous r15 into r13
0x2e58ca: 	moving previous r13 into rdi
hlt at 0x83f
empty hlt
Empty unwind
0x   8e0: 	ContextRecord to rbx
0x2e599c: 	moving previous rdi into rdi
0x   8eb: 	moving previous MxCsr into r11d
0x2e5a03: 	add r11, previous r13
0x   8f6: 	mov bpl, byte ptr [r11]
0x   8f9: 	mov dil, bpl
...
```

An in depth reading of the above function is not needed, all you need to know is that the first byte of the result of multiplying a character input by some constant has 0x8d added to it via the 2d array. But with an overflow of sorts allowed. And if you follow further down, the exact same pattern happens 3 more times, but with different constants, added to higher and higher bytes.

In effect, the operation of the 2d array is done to the entire register. These bytes can be extracted. And so can the operations done too.

```python
... #continuing the script above in the loop
arrayOp = '?'
arrayConst = '0xXXXXXXXX'
#arrayop finding
arrayOpMatch = None
for m in range(i, i+80):
	try:
		if "whitebox" in lines[m]:
			arrayOpMatch = re.search(r'0x[\s0-9a-f]{6}: \twhitebox \b([\w\-]+)\b',lines[m])
			if arrayOpMatch:
				arrayOp = arrayOpMatch.group(1)
				match arrayOp:
					case 'x_XOR_y':
						arrayOp = '^'
					case 'x_greater_then_y_bitset':
						arrayOp = '-'
					case '255-x_greater_than_y_bitset':
						arrayOp = '+'
				break
	except:
		arrayOp = 'X('
		if len(results) == 254:
			pass
		else:
			print("err",(m),len(results))
		pass

if arrayOp == '+':
	const1 = 'whitebox x+y_AND_0xff'
elif arrayOp == '-':
	const1 = 'whitebox y_minus_x'
elif arrayOp == '^':
	const1 = 'whitebox x_XOR_y'

pos = 0
trueval = 0
for n in range (i,i+1000):
	try:
		if const1 in lines[n]:
			for o in range(n,n+15):
				if 'UWOP_ALLOC_LARGE' in lines[o]:
					pos += 1
					hexval = int(lines[o][25:],16)
					if lines[o][17] == '3':
						hexval = hexval // 8
					hexval = hexval << (pos-1)*8
					trueval += hexval
					break
				if 'UWOP_ALLOC_SMALL' in lines[o]:
					pos += 1
					break
			if pos == 4:
				break
	except:
		arrayOp = 'X('
		if len(results) == 254:
			pass
		else:
			print("err",(m),len(results))
		pass

arrayConst = hex(trueval)
```

```
sum += userflag[04] * 0xef7a8c
sum += 0x9d865d8d
sum -= userflag[24] * 0x45b53c
sum += 0x18baee57
sum -= userflag[24] * 0xe4cf8b
sum -= 0x913fbbde
sum -= userflag[08] * 0xf5c990
sum += 0x6bfaa656
sum ^= userflag[20] * 0x733178
sum ^= 0x61e3db3b
sum ^= userflag[16] * 0x9a17b8
sum -= 0xca2804b1
sum ^= userflag[12] * 0x773850
sum ^= 0x5a6f68be
sum ^= userflag[28] * 0xe21d3d
sum ^= 0x5c911d23
test
```

Even then, this doesn't fully encompass all of the operations done upon the final value.

Theres one... final.... operation...

### Final pattern: One more round

If you look what happens after all of the bytes of the 8th round of operations, you will not find tests

Now, word of warning: my methodology was flawed, and did not replicate the 9th round of array operations. This involved correcting each check by an amount determined manually. even then, most tests were still not replicated correctly. Most however, were replicated well enough to require adjustments to the value, after manually checking.

If you anchored a search from each `test`, and looked at previous operations, you would see that the 2d array was used again, exclusively for `y_minus_x`. However, if you observe the final values, you would see the opposite, some value being added to the sum. But, if you observe the operation in full, you will see for some, there is the value `0xff` being subtracted from nothing, and others there is not, and this correlates to the addition.

This is how you can extract bytes, or at least what my best effors were to find the bytes


Here is the code I used to generate the extra operation below.

```python
if 'test' in line:
	extraOp = 'TOUCH'
	count= 0
	trueval=0
	for y in range(i,max(0,i-10000),-1):
		if "whitebox" in lines[y]:
			if 'y_minus_x' in lines[y]:
				count += 1
				if count == 1:
					extraOp = '-'
					for z in range(y,y+15):
						if 'UWOP_ALLOC_LARGE' in lines[z] and ('0xff' in lines[z] or '0x7f8' in lines[z]):
							extraOp = '+'
							break
				if count > 1 and extraOp == '+':
					for z in range(y,y+15):
						if 'UWOP_ALLOC_LARGE' in lines[z]:
							if '3 bytes' in lines[z]:
								hexval = int(lines[z][25:],16)//8
							else:
								hexval = int(lines[z][25:],16)
							pos = 8-count
							realval = (hexval^0xff)<<pos*8
							trueval += realval
							break
				if count > 1 and count < 7 and extraOp == '-':
					for z in range(y,y+15):
						if 'UWOP_ALLOC_LARGE' in lines[z]:
							if '3 bytes' in lines[z]:
								hexval = int(lines[z][25:],16)//8
							else:
								hexval = int(lines[z][25:],16)
							pos = max(5-count,0)
							realval = (hexval)<<pos*8
							trueval += realval
							break
				if count == 8:
					break
	res = results.pop()
	res['extraOp'] = extraOp
	res['extraConst'] = hex(trueval)
	results.append(res)
```

## Solving the Flag, symbolically

So, we have the operations that lead to 32 checks (approximately). What now? Well, its to turn these checks into python code that will function as emulation of the program.

```python
for idx, result in enumerate(results):
    if idx % 8 == 0:
        print(f"def check{idx//8}:")
    print(f"\tsum {result['charOp']}= userflag[{result['char']:02d}] * {result['mov + add']}")
    print(f"\tsum {result['arrayOp']}= {result['arrayConst']}")
    if idx % 8 == 7 and idx != 0:
        print(f"\tsum {result['extraOp']}= {result['extraConst']}")
        print('\treturn sum\n\n\n')
```
result:
```python
def check0(userFlag):
	sum += userflag[04] * 0xef7a8c
	sum += 0x9d865d8d
	sum -= userflag[24] * 0x45b53c
	sum += 0x18baee57
	sum -= userflag[24] * 0xe4cf8b
	sum -= 0x913fbbde
	sum -= userflag[08] * 0xf5c990
	sum += 0x6bfaa656
	sum ^= userflag[20] * 0x733178
	sum ^= 0x61e3db3b
	sum ^= userflag[16] * 0x9a17b8
	sum -= 0xca2804b1
	sum ^= userflag[12] * 0x773850
	sum ^= 0x5a6f68be
	sum ^= userflag[28] * 0xe21d3d
	sum ^= 0x5c911d23
	sum += 0x7e9b8586 + ADJUST
	return sum
```

But, how do we get the adjustment values without trying to pass each check one by one in a debugger? Well, this is where ghidra comes to the rescue. for the 32 checks, you simply remove the `cmovne`.
```
0x 4751a: 	test r12, r12
0x356d96: 	lea r13, [rip - 0x30f872]
0x 47524: 	cmovne r13, rsi
0x 47528: 	jmp r13
```

You can edit the program itself, rather than the heap. just go to the offset plus `0x95ef0`. Hit `D` to decode the instruction and make sure you are at the right place. Then, `Ctrl+Alt+G` to alter the instruction to something like `nop RAX` which should be the same length as `cmovne...`.

Then, in the debugger, find the locations for each test value, and set a breakpoint for each one based off of the location of the first instruction in the "virtual" program. I made a simple python script to generate the command for `x64dbg` in python. A different debugger might be different command wise.
```python
heaploc = 0x0000+0x69d*0x10000

print("bp",hex(0x179fd+heaploc),end=';')
print("bp",hex(0x2f386+heaploc),end=';')
print("bp",hex(0x4751a+heaploc),end=';')
print("bp",hex(0x5d2cd+heaploc),end=';')
print("bp",hex(0x7230b+heaploc),end=';')
print("bp",hex(0x8917b+heaploc),end=';')
print("bp",hex(0xa0de8+heaploc),end=';')
print("bp",hex(0xb7d00+heaploc),end=';')
print("bp",hex(0xd0742+heaploc),end=';')
print("bp",hex(0xe7b7b+heaploc),end=';')
print("bp",hex(0xff3a3+heaploc),end=';')
print("bp",hex(0x1164ea+heaploc),end=';')
print("bp",hex(0x12ce52+heaploc),end=';')
print("bp",hex(0x14492b+heaploc),end=';')
print("bp",hex(0x15ec1e+heaploc),end=';')
print("bp",hex(0x176fbd+heaploc),end=';')
print("bp",hex(0x190732+heaploc),end=';')
print("bp",hex(0x1a5a58+heaploc),end=';')
print("bp",hex(0x1bc75d+heaploc),end=';')
print("bp",hex(0x1d572b+heaploc),end=';')
print("bp",hex(0x1ecdf1+heaploc),end=';')
print("bp",hex(0x205671+heaploc),end=';')
print("bp",hex(0x21b636+heaploc),end=';')
print("bp",hex(0x22f442+heaploc),end=';')
print("bp",hex(0x243e47+heaploc),end=';')
print("bp",hex(0x25a19e+heaploc),end=';')
print("bp",hex(0x26ec62+heaploc),end=';')
print("bp",hex(0x285d0b+heaploc),end=';')
print("bp",hex(0x29e558+heaploc),end=';')
print("bp",hex(0x2b5f19+heaploc),end=';')
print("bp",hex(0x2cd429+heaploc),end=';')
```

And then, adjust the `ADJUST` value until it matches what is in the program. This worked for about 2/3rds of the checks. About 6 or so needed the 8th and 9th round to be combined, and 1/3rd did not work no matter what. I theorize its the difference between how python manipulates the values without undeflows and overflows, and how the program has the limitation of registers.

We now can replicate about 2/3rds of the checks, now it is time for symbolic execution.

I used z3 in order to solve this challenge. z3 is a sat solver, meaning it is built to solve a set of equations that has a singular answer for the variables within. When using z3, you need to make sure that the equations you feed through it are solvable.

Here is how I set up my z3 instance

```python
from z3 import *

ADJUST = 0 # implemented by default, adjusted for each round

def check1(userflag):
... # checks 1 through 32

inp = [BitVec(f'inp{i}', 64) for i in range(32)]  

solver = Solver()
set_param("parallel.enable", True)
for i in range(32):
    solver.add(inp[i] >= 0x24)
    solver.add(inp[i] <= 0x7a)
solver.add(check1(inp) == 0)
... #all 32 checks are added
set_param("parallel.enable", True)
while solver.check() == sat:
	model = solver.model()
	solution = []
	for i in range(32):
		solution.append(chr(model[inp[i]].as_long()))
	valstr = ''.join(solution).encode()
	print("Solution found:", valstr)
```

If you have all 32 checks verified (which I was eventually able to do), the z3 instance will only take a few seconds. However, the less and less checks you have verifed, the longer and harder the z3 instance will be on your computer. If you manage to get z3 to spit out multiple solutions, as I did during the competiton, you can take shortcuts with the program. This is how I eventually got the flag with only 2/3ds of it working at the time.

```python
# Solution found: b'  _4 way _k3 p_m v1n _an _m0 ing'
# solver.add(inp[0]  == ord(''))
# solver.add(inp[1]  == ord(''))
solver.add(inp[2]  == ord('_'))
solver.add(inp[3]  == ord('4'))
# solver.add(inp[4]  == ord(''))
solver.add(inp[5]  == ord('w'))
solver.add(inp[6]  == ord('a'))
solver.add(inp[7]  == ord('y'))
# solver.add(inp[8]  == ord('s'))
solver.add(inp[9]  == ord('_'))
solver.add(inp[10] == ord('k'))
solver.add(inp[11] == ord('3'))
# solver.add(inp[12] == ord('3'))
solver.add(inp[13] == ord('p'))
solver.add(inp[14] == ord('_'))
solver.add(inp[15] == ord('m'))
# solver.add(inp[16] == ord(''))
solver.add(inp[17] == ord('v'))
solver.add(inp[18] == ord('1'))
solver.add(inp[19] == ord('n'))
solver.add(inp[20] == ord('g')) # final guess that got me the flag
solver.add(inp[21] == ord('_'))
solver.add(inp[22] == ord('a'))
solver.add(inp[23] == ord('n'))
# solver.add(inp[24] == ord('d'))
solver.add(inp[25] == ord('_'))
solver.add(inp[26] == ord('m'))
solver.add(inp[27] == ord('0'))
# solver.add(inp[28] == ord(''))
solver.add(inp[29] == ord('i'))
solver.add(inp[30] == ord('n'))
solver.add(inp[31] == ord('g'))
```

Either way, this will get you the flag!

```
Solution found: b'$$_4lway5_k3ep_mov1ng_and_m0ving'
```

The files used were `flare11_chall9_collapsePointers.py`,  `flare11_chall9_createPy.py`,  `flare11_chall9_disasm1.py`,  `flare11_chall9_finalsolve.py`.` flare11_chall9_solve.sh` is the intended order of execution, run the 3 line script if you want an idea of workflow.

P.S: if you wish to read the original code I wrote to emulate the `UNWIND_CODE`s, please see `flare11_chall9_realInstructions.py`. Be warned, it was made in a live environment, meaning its very messy.

Credit to [https://github.com/Salt-Mc/Flare-On/tree/main](https://github.com/Salt-Mc/Flare-On/tree/main "https://github.com/Salt-Mc/Flare-On/tree/main") for letting me verify some of the values (the solution wouldn't have worked without referencing your results, thanks)