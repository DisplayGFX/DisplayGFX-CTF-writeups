ReRop
===

HTB Reversing Challenge

Place Achieved: #131

By DisplayGFX
___
Description
```
How is that even possible, I thought it was only an exploitation technique, but maybe it has other applications as well
```

We have only one file, `rerop`, which is an ELF executable.

## Initial Enumeration

And shockingly straightforward... at first. Anyways, lets see what the main does.

```c
undefined8 main(void)

{
  size_t sVar1;
  
  printf("Enter the flag: ");
  fgets(buf,64,(FILE *)stdin);
  sVar1 = strcspn(buf,"\n");
  buf[sVar1] = 0;
  check(data);
  puts(buf);
  return 0;
}
```

This is accurate to the binary, nothing missing or anything extraneous in here. The only custom one that seems to stand out is `check(data)`. What seems to be in there?

```
void check(void){
  return;
}
```

Well, that cant be right, seems like ghidra doesnt clock what is happening, lets take a look at the assembly.

```
                             undefined check()
             undefined         AL:1           <RETURN>
                             check                                           XREF[3]:     Entry Point(*), main:0040182d(c), 
                                                                                          004b4b58(*)  
        004017b5 f3 0f 1e fa     ENDBR64
        004017b9 48 8d 27        LEA        RSP,[RDI]
        004017bc c3              RET

```

So, it takes the stack, and writes the address to the source pointer. Which means it takes whatever value that is on the stack, and jumps to that.

Ahhh, thats why its called rerop. `check` will basically load the `data` global variable, and move the pointer to it, in effect, replacing the stack with one in the program memory. Then instantly returns. Then, in the new stack, it returns to segments of code that end in `RET`. Essentially building the assembly one return at a time. This is a technique called Return oriented programming or ROP for short, usually used with shellcode instead of in the program itself. One wonders what magic code the program was written in to make this possible.

Alright. So, to do this, we need to change the form of `data`. in the code, its broken up as `undefined1[10000]`. but RSP is 8 bytes long (x64 refers to the bits for any given address, so... 8 bytes = 64 bits). Lets redefine it as `undefined8[1250]`. Though, if you want to trim it down, you can define the first element as `undefined8[609]`.

Anyways, lets see if the first few ROP instructions will get us anywhere. it will be handy to also keep somewhere on a scratch pad a running counter of the RSP. Oh, and to be clear, RET will pop the stack, meaning the stack pointer is advanced downwards, so any time RET is called, add 8 to the RSP register.

First thing to note, before getting into the code I wrote to disassemble this monstrositiy: There is an anti-ghidra trick.

```
        00450ec4 48 83 c4 58     ADD        RSP,0x58
        00450ec8 c3              RET
```
This is the code you will see when you disassemble the binary with the automatic scripts. It looks like its jumping up `0x58` to another place on the stack. but if you will notice, the address is `0x450ec4`. When, in fact, the instruction will point to `0x450ec7`. Thats a different instruction location within the one we currently have!

So, to get the proper instruction, hit `C` to clear the code disassembly, and then hit `D` at the right address, and suddenly, it looks a lot more sensible.
```
        00450ec7 58              POP        RAX
        00450ec8 c3              RET
```

## Program Analysis

After painstaking recreation, I was able to get the original program back out. Now, lets go through the program. Each location hex represents the location on the stack.


```
0x4c5100:        pop    rax (0x65)
0x4c5110:        pop    rdi (0x0)
0x4c5120:        pop    rsi (0x1)
0x4c5130:        pop    rdx (0x0)
0x4c5140:        syscall         :ptrace(0,1,0,0)

```

First, it will run a check to make sure that it is not being debugged. It does this by calling ptrace on itself, with a `PTRACE_DEBUGME` flag. This will return `-1` if it is already being debuged, and `0` if not.

```
0x4c5148:	 mov	rdi, rax
0x4c5150:	 pop	rax (0x1198)
0x4c5160:	 mov	rsi, rax
0x4c5160:	 xor	rbx, rbx
0x4c5160:	 test	rdi, rdi
0x4c5160:	 cmovs	rbx, rsi
0x4c5160:	 add	rsp, rbx
```

Which is checked for here. This will move RSP to an exit stackpoint, seen below.

```
0x4c6300:	 pop	rax (0x706f4e6d31335b1b)
0x4c6310:	 pop	rdx (0x4c57e8)
0x4c6320:	 mov	qword ptr [rdx], rax
0x4c6328:	 pop	rax (0xa6d305b1b65)
0x4c6338:	 pop	rdx (0x4c57f0)
0x4c6348:	 mov	qword ptr [rdx], rax
0x4c6350:	 pop	rax (0x1)
0x4c6360:	 pop	rdi (0x1)
0x4c6370:	 pop	rsi (0x4c57e8)
0x4c6380:	 pop	rdx (0xe)
0x4c6390:	syscall		:write(1,0x4c57e8,14,0)
output:  Nope
```

This basically writes 8 bytes to a fixed location in the program, and then another 8 (6 really) bytes. then, writes the string to stdout, which I have calculated, which is `Nope` that is colored with ANSI escape codes.

After the anti-debug code, we get to the meat and potatoes of this binary.
```
#before any loop
0x4c5168:	 pop	rdx (0x0)
...
0x4c53b8:	 pop	rdi (0x4c7820)
0x4c53c8:	 pop	rax (0x0)
0x4c53d8:	 add	rdi, rax
0x4c53e0:	 mov	rax, rdi
0x4c53e8:	 movzx	rax, byte ptr [rax]
0x4c53f0:	 mov	rdi, rax
0x4c53f8:	 pop	rax (0x0)
0x4c5408:	 add	rdi, rax
0x4c5410:	 pop	rax (0x5)
0x4c5420:	 xor	rdi, rax
0x4c5428:	 pop	rax (0x4d)
0x4c5438:	 sub	rdi, rax
0x4c5440:	 mov	esi, 1
0x4c5440:	 test	rdi, rdi
0x4c5440:	 cmovne	rdx, rsi
```

This will be an example of the decoding, taken from the middle of the program. Lets go chunk by chunk.

```
0x4c53b8:	 pop	rdi (0x4c7820)
0x4c53c8:	 pop	rax (0x0)
0x4c53d8:	 add	rdi, rax
0x4c53e0:	 mov	rax, rdi
0x4c53e8:	 movzx	rax, byte ptr [rax]
0x4c53f0:	 mov	rdi, rax
```

Here is the buffer location being loaded, and rax being loaded with `0`, adding the two together, and then taking the byte at that location, and loading it into rdi. In other words, we are loading the first character in buffer (the input) into rdi.

```
0x4c53f8:	 pop	rax (0x0)
0x4c5408:	 add	rdi, rax
0x4c5410:	 pop	rax (0x5)
0x4c5420:	 xor	rdi, rax
0x4c5428:	 pop	rax (0x4d)
0x4c5438:	 sub	rdi, rax
```

Here, the program is adding 0 to the byte we have, then XORing the byte with `5`, and then subtracting from that total `0x4d`. Why is what we will get to after the last block.

```
0x4c5440:	 mov	esi, 1
0x4c5440:	 test	rdi, rdi
0x4c5440:	 cmovne	rdx, rsi
```

Here we can see why it does this, it moves `1` into esi, and will conditionally move `1` into rdx if rdi is not zero. 

Towards the end, there is a check of `rdx` to see if it is zero or non-zero
```
0x4c61c8:	 mov	r8, rdx
0x4c61d0:	 mov	rdx, r8
0x4c61d8:	 pop	rax (0x110)
0x4c61e8:	 mov	rsi, rax
0x4c61e8:	 xor	rbx, rbx
0x4c61e8:	 test	rdx, rdx
0x4c61e8:	 cmovne	rbx, rsi
0x4c61e8:	 add	rsp, rbx
```

This jumps to the same code printing `Nope` later down in the ROPStack

So, what character would get us a pass on this check? Well, the operations that the program just did are as follows.
$(char + \texttt{0x0}) \oplus \texttt{0x5} - \texttt{0x4d} = 0$
so, if we want to reverse the encryption, we can do the following
$\texttt{0x4d} \oplus \texttt{0x5} - \texttt{0x0} = char$
So, doing this math, what does that get us?
`H`
Thats the first character of the flag, as all flags (usually) start with `HTB{`!

To generalize, the operations done are
$(char + pos) \oplus \texttt{0x5} - \texttt{0x4d}$
And to reverse the encryption
$encchar \oplus \texttt{0x5} - pos = char$

So, perform this operation on all of the characters pulled from the ROPstack, and you get...

The flag!
https://labs.hackthebox.com/achievement/challenge/158887/498

After passing the flag character check, assuming you give it the right flag, it will run the following code.
```
0x450ec7:       pop     rax     : 0x726f436d32335b1b
0x458142:       pop     rdx     : 0x4c57e8
0x419ad8:       mov     qword ptr [rdx], rax
0x450ec7:       pop     rax     : 0x616c462074636572
0x458142:       pop     rdx     : 0x4c57f0
0x419ad8:       mov     qword ptr [rdx], rax
0x450ec7:       pop     rax     : 0xa6d305b1b2167
0x458142:       pop     rdx     : 0x4c57f8
0x419ad8:       mov     qword ptr [rdx], rax
0x450ec7:       pop     rax     : 0x0
0x458142:       pop     rdx     : 0x4c5800
0x419ad8:       mov     qword ptr [rdx], rax
0x450ec7:       pop     rax     : 0x1
0x401eef:       pop     rdi     : 0x1
0x409f1e:       pop     rsi     : 0x4c57e8
0x458142:       pop     rdx     : 0x18
0x4303542:      syscall         :write(1,0x4c57e8,24,0)
output:  Correct Flag!
0x450ec7:       pop     rax     : 0x3c
0x401eef:       pop     rdi     : 0x0
0x4303542:      syscall         :exit(0)
```

This piece of code loads in the string, and calls `write` to print `Correct Flag!` with ANSI escape characters.

Below is the code I used to render the flag and the assembly used in this writeup

```python
import struct
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

# dev options
debug = True

# magic numbers
PROG_OFFSET = 0x400000
READ_OFFSET = 0x1000  # python for some reason, hacks off the header information. So much for "read bytes"
STACK_START = 0xC5100
STACK_END   = 0x4c63c0
FLAG_BUFFER = 0x4C7820
flag = [" "] * 30

with open("rerop", "rb") as x:
    PROG_BYTES = bytearray(x.read())  # bytearray allows for modification


def get_ropbytes(addr: int):
    ropbytes = PROG_BYTES[
        addr - PROG_OFFSET - READ_OFFSET : addr - PROG_OFFSET - READ_OFFSET + 8
    ]
    return struct.unpack_from("<Q", ropbytes)[0]


# start of ROPstack
md = Cs(CS_ARCH_X86, CS_MODE_64)
# supposedly will skip over invalid instructions. Did not work at all.
# md.skipdata = True

regs = {
    "rax":0,
    "rbx":0,
    "rcx":0,
    "rdx":0,
    "rdi":0,
    "rsi":0,
    "rsp":STACK_START + PROG_OFFSET,
}

next_index = False
flag_index = 0

while True:
    rop_start = get_ropbytes(regs["rsp"])
    for i in md.disasm(PROG_BYTES[rop_start - PROG_OFFSET :], rop_start):
        if regs["rsp"] >= STACK_END:
            exit()
        if debug:
            match i.mnemonic:
                case "pop":
                    print("0x{:x}:\t".format(regs['rsp']),f"{i.mnemonic}\t{i.op_str} ({hex(get_ropbytes(regs['rsp']+8))})")
                case "ret":
                    pass
                case "syscall":
                    match regs["rax"]:
                        case 0x65:  # ptrace
                            print(f"{hex(regs['rsp'])}:\tsyscall\t\t:ptrace({regs['rdi']},{regs['rsi']},{regs['rdx']},{regs['rcx']})")
                        case 60:  # exit
                            print(f"{hex(regs['rsp'])}:\tsyscall\t\t:exit({regs['rdi']})")
                            print("program exited")
                            if regs["rdi"] == 0:
                                print("\rFlag:", "".join(flag))
                        case 1:
                            print(f"{hex(regs['rsp'])}:\tsyscall\t\t:write({regs['rdi']},{hex(regs['rsi'])},{regs['rdx']},{regs['rcx']})")
                            offset = regs["rsi"] - PROG_OFFSET - READ_OFFSET
                            write_string = PROG_BYTES[offset : offset + regs["rdx"]]
                            print("output: ", write_string.decode())
                        case _:
                            print(f"{hex(regs['rsp'])}:\tsyscall\t\t: you missed a spot, ({hex(regs['rax'])})")
                case _:
                    print("0x{:x}:\t".format(regs['rsp']),f"{i.mnemonic}\t{i.op_str}")
        match i.mnemonic:
            case "ret": # Going back to the ROPStack
                regs["rsp"] += 0x8
                break
            case "pop": # Loads values from ROPStack into registers
                regs["rsp"] += 0x8
                if get_ropbytes(regs["rsp"]) == FLAG_BUFFER:
                    next_index = True
                regs[i.op_str] = get_ropbytes(regs["rsp"])
                if i.op_str == "rax" and next_index:
                    flag_index = regs["rax"]
                    next_index = False
            case "syscall": # Direct syscall, thankfully only 3 syscalls in this program, only 1 that matters for emulation
                if regs["rax"] == 0x65:  # ptrace
                    regs["rax"] = 0  # successful ptrace value, only fails if its being debugged.
            case "cmovne" | "cmovs": # debugging pivot point, in case you want to look at other paths
                if i.op_str != "rdx, rsi":  # skips per character comparisons
                    pass
                pass
            case "sub": # Specific instruction only used by encrypt code
                if i.op_str == "rdi, rax":
                    try:
                        char = chr((((regs["rax"]) ^ 0x5) - flag_index))
                    except ValueError:
                        print("something happened")
                        char = ""
                    flag[flag_index] = char
                    if not debug:
                        sys.stdout.write("\r" + "".join(flag))
            case "xor": # specific XOR instructions that impact execution
                if i.op_str == "rbx, rbx":
                    regs["rbx"] = 0
                elif i.op_str == "rdi, rax":  # xor of characters we want.
                    regs["rdi"] ^= regs["rax"]
                else:
                    print(i.address)
            case "mov": # mov and add are executed in this program
                if "esi" in i.op_str and "1" in i.op_str: # this intercepts a specific instruction
                    regs["rsi"] = 1
                # if written to program, get source and write over PROG_BYTES.
                elif "qword ptr [" in i.op_str and "]," in i.op_str:
                    dst = i.op_str.split(",")[0].strip()
                    src = i.op_str.split(",")[1].strip()
                    dst_addr = regs[dst.split("[")[1].strip(" ]")]
                    src_value = regs[src]
                    offset = dst_addr - PROG_OFFSET - READ_OFFSET
                    PROG_BYTES[offset : offset + 8] = struct.pack("<Q", src_value)
                else:
                    dst = i.op_str.split(",")[0]
                    src = i.op_str.split(",")[1].strip(" ")
                    regs[dst] = regs[src]
            case "add":
                dst = i.op_str.split(",")[0]
                src = i.op_str.split(",")[1].strip(" ")
                regs[dst] += regs[src]
            case "movzx" | "test": #ignored instructions
                pass
            case _:# if not caught by above, print the instruction
                print("{}\t{}".format(i.mnemonic, i.op_str))
```