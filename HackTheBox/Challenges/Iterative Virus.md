Iterative Virus
===

HTB Reversing Challenge

By DisplayGFX
___


Only one file, `HELLO_WORLD_INFECTED_!!!.exe`.
## Initial Enumeration
Lets look at what the binary says. After a jump, the first interesting function call is the first call.

After some stack storage shenanigans, we have this series of `MOV`s. GS:\[0x30] is a register that holds a pointer to the thread environment block. which contains a great amount of data about the current thread. You can see navigation towards a certain aspect in this block.

In Windows, GS\[0x30\] has a special meaning. [This register contains the TEB, which contains a lot of information for the thread, if not all of it.](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block) From there, we can use WinDbg to find what data it is looking for.

```
   14001c10e 65 48 8b        MOV        RAX,qword ptr GS:[offset ->ExceptionList]        = ff00000000
			 04 25 30 
			 00 00 00
   14001c117 45 33 c9        XOR        R9D,R9D
   14001c11a 48 8b 50 60     MOV        RDX,qword ptr [RAX + offset ProcessEnvironment   = 00000000
   14001c11e 48 8b 42 18     MOV        RAX,qword ptr [RDX + 0x18]
   14001c122 48 8b 50 20     MOV        RDX,qword ptr [RAX + 0x20]
   14001c126 48 8b 02        MOV        RAX,qword ptr [RDX]
   14001c129 48 8b 10        MOV        RDX,qword ptr [RAX]
   14001c12c 4c 8b 5a 20     MOV        R11,qword ptr [RDX + 0x20]
   14001c130 4c 89 19        MOV        qword ptr [RCX],R11
   14001c133 49 63 43 3c     MOVSXD     RAX,dword ptr [R11 + 0x3c]
   14001c137 42 8b 8c        MOV        ECX,dword ptr [RAX + R11*0x1 + 0x88]
			 18 88 00 
			 00 00
```
So this whole thing will gather the address of the Export table, essentially functions that are accessible to the outside programs. From here, the program is looking for a specific function.

```

       14001c13f 42 8b 44        MOV        EAX,dword ptr [RCX + R11*0x1 + 0x20]
                 19 20
       14001c144 42 8b 7c        MOV        EDI,dword ptr [RCX + R11*0x1 + 0x18]
                 19 18
       14001c149 42 8b 5c        MOV        EBX,dword ptr [RCX + R11*0x1 + 0x1c]
                 19 1c
```
This gets the string for the function, and the below hashes the string, and compares it with a static hash

```
       14001c14e 4a 8d 14 18     LEA        RDX,[RAX + R11*0x1]
       14001c152 85 ff           TEST       EDI,EDI
       14001c154 74 40           JZ         LAB_14001c196
       14001c156 48 2b d8        SUB        RBX,RAX
                             LAB_14001c159                                   XREF[1]:     14001c194(j)  
       14001c159 48 63 02        MOVSXD     RAX,dword ptr [RDX]
       14001c15c 83 c9 ff        OR         ECX,0xffffffff
       14001c15f 4c 63 04 1a     MOVSXD     R8,dword ptr [RDX + RBX*0x1]
       14001c163 49 03 c3        ADD        RAX,R11
       14001c166 4d 03 c3        ADD        R8,R11
       14001c169 44 8a 10        MOV        R10B,byte ptr [RAX]
       14001c16c 45 84 d2        TEST       R10B,R10B
       14001c16f 74 19           JZ         LAB_14001c18a
                             LAB_14001c171                                   XREF[1]:     14001c180(j)  
       14001c171 48 ff c0        INC        RAX
       14001c174 f2 41 0f        CRC32      ECX,R10B
                 38 f0 ca
       14001c17a 44 8a 10        MOV        R10B,byte ptr [RAX]
       14001c17d 45 84 d2        TEST       R10B,R10B
       14001c180 75 ef           JNZ        LAB_14001c171
       14001c182 81 f9 82        CMP        ECX,0xbc553b82
                 3b 55 bc
       14001c188 74 19           JZ         LAB_14001c1a3
                             LAB_14001c18a                                   XREF[1]:     14001c16f(j)  
       14001c18a 41 ff c1        INC        R9D
       14001c18d 48 83 c2 04     ADD        RDX,0x4
       14001c191 44 3b cf        CMP        R9D,EDI
       14001c194 72 c3           JC         LAB_14001c159
```
Then, at the end of this function, it will compare the hash to a precomputed hash.

This hash is for a function called GetProcessAddress, which, given a string, will return the address for that function. Which will come in handy later.

Back to the main program, there is another call soon after, and a value and string buffer is passed in, here's the code.
```c
char * getStringArray(char *param_1,int param_2)

{
  if (param_2 == 5) {
    *(undefined4 *)param_1 = L'\x74697845';
    *(undefined4 *)(param_1 + 4) = L'\x636f7250';
    *(undefined8 *)(param_1 + 8) = L'\x00737365';
  }
  else if (param_2 == 6) {
    *(undefined4 *)param_1 = L'\x61657243';
    *(undefined4 *)(param_1 + 4) = L'\x69466574';
    *(undefined8 *)(param_1 + 8) = L'\x0041656c';
  }
  else if (param_2 == 7) {
    *(undefined4 *)param_1 = L'\x46746547';
    *(undefined4 *)(param_1 + 4) = L'\x53656c69';
    *(undefined8 *)(param_1 + 8) = L'\x00657a69';
  }
  else if (param_2 == 8) {
    *(undefined4 *)param_1 = L'\x61657243';
    *(undefined4 *)(param_1 + 4) = L'\x69466574';
    *(undefined4 *)(param_1 + 8) = L'\x614d656c';
    *(undefined4 *)(param_1 + 0xc) = L'\x6e697070';
    *(undefined8 *)(param_1 + 0x10) = L'䅧';
  }
  else if (param_2 == 9) {
    *(undefined4 *)param_1 = L'\x5670614d';
    *(undefined4 *)(param_1 + 4) = L'\x4f776569';
    *(undefined4 *)(param_1 + 8) = L'\x6c694666';
    *(undefined4 *)(param_1 + 0xc) = L'e';
  }
  else if (param_2 == 10) {
    *(undefined4 *)param_1 = L'\x78652e2a';
    *(undefined4 *)(param_1 + 4) = L'e';
  }
  else if (param_2 == 0xc) {
    *(undefined4 *)param_1 = L'\x646e6946';
    *(undefined4 *)(param_1 + 4) = L'\x73726946';
    *(undefined4 *)(param_1 + 8) = L'\x6c694674';
    *(undefined4 *)(param_1 + 0xc) = L'䅥';
  }
  else if (param_2 == 0xd) {
    *(undefined4 *)param_1 = L'\x646e6946';
    *(undefined4 *)(param_1 + 4) = L'\x7478654e';
    *(undefined4 *)(param_1 + 8) = L'\x656c6946';
    *(undefined4 *)(param_1 + 0xc) = L'A';
  }
  else if (param_2 == 0xe) {
    *(undefined4 *)param_1 = L'\x646e6946';
    *(undefined4 *)(param_1 + 4) = L'\x736f6c43';
    *(undefined8 *)(param_1 + 8) = L'e';
  }
  else {
    if (param_2 != 0xf) {
      return (char *)0x0;
    }
    *(undefined4 *)param_1 = L'\x736f6c43';
    *(undefined4 *)(param_1 + 4) = L'\x6e614865';
    *(undefined8 *)(param_1 + 8) = L'\x00656c64';
  }
  return param_1;
}
```

Looks messy, that is because Ghidra doesn't know how to handle stack strings (at the time of writing, it does now if you specify one of the variables as a `char *` string). Here is the code cleaned from this, and you will see how it makes more sense.

```c
char * getStringArray(char *param_1,int param_2){
  if (param_2 == 5) {
    strcpy(param_1, "ExitProcess");
  }
  else if (param_2 == 6) {
    strcpy(param_1, "CreateFileA");
  }
  else if (param_2 == 7) {
    strcpy(param_1, "GetFileSize");
  }
  else if (param_2 == 8) {
    strcpy(param_1, "CreateFileMappingA");
  }
  else if (param_2 == 9) {
    strcpy(param_1, "MapViewOfFile");
  }
  else if (param_2 == 0xa) {
    strcpy(param_1, "*.exe");
  }
  else if (param_2 == 0xc) {
    strcpy(param_1, "FindFirstFileA");
  }
  else if (param_2 == 0xd) {
    strcpy(param_1, "FindNextFileA");
  }
  else if (param_2 == 0xe) {
    strcpy(param_1, "FindClose");
  }
  else if (param_2 != 0xf) {
    strcpy(param_1, "CloseHandle");
  }
  else{
	  return 0;
  }
  return param_1;
}
```

So, what the program does after this is to take every string except for `"*.exe"` and will get the functions that are named, and return the pointer to those functions. The C code in the main function looks something like this.

In ghidra, if you want it to be recognized as a function, rather than a random pointer, you can set the variable as a pointer to the correct function, so in the below case, you retype it to `ExitProcess *`

```c
getprocessaddress = Get_getprocessaddress();
strPtr = StringLookup(local_1d8,5); //ExitProcess string
ExitProcess = (*getprocessaddress)(NULL,strPtr);//
```

For each and every function listed above. 

After, it pulls a variable from the program binary, and sees if it's exactly 5. if not, it will jump to another part of the program. Right now, it's set to 1. This will grab the offset to an encrypted function.

```
       14001c470 45 84 f6        TEST       R14B,R14B
       14001c473 75 0c           JNZ        LAB_14001c481
       14001c475 48 bb 09        MOV        RBX,0x28c8aa0746a75909
                 59 a7 46 
                 07 aa c8 28
       14001c47f eb 4a           JMP        LAB_14001c4cb

```

After this, it will compare the number to a range of 0 to 4, and move a certain number into RBX. See the above for an example of what this looks like.

Then, it will get into the meat of the program.

```
       14001c4da 48 8b c8        MOV        RCX,RAX; (*.exe string)
       14001c4dd 48 8d 55 90     LEA        RDX=>local_188,[RBP + -0x70]
       14001c4e1 41 ff d5        CALL       FindFirstFileA
       14001c4e4 48 89 44        MOV        qword ptr [RSP + local_1a8],RAX
                 24 70
       14001c4e9 4c 8b e0        MOV        GetProcessAddress,RAX
       14001c4ec 48 83 f8 ff     CMP        RAX,-0x1
       14001c4f0 0f 84 cd        JZ         LAB_14001c7c3
                 02 00 00
```

So, this block will find the first file that ends with `.exe`, and return a handle for searching if it finds something. If it doesn't find anything, it will jump away to a part of the program which, eventually, will restart the program.

Next step is below

```
       14001c4f6 33 ff           XOR        EDI,EDI
                             LAB_14001c4f8                                   XREF[1]:     14001c7b7(j)  
       14001c4f8 45 33 c9        XOR        R9D,R9D
       14001c4fb 48 89 7c        MOV        qword ptr [RSP + local_1e8],RDI
                 24 30
       14001c500 c7 44 24        MOV        dword ptr [RSP + local_1f0],0x80
                 28 80 00 
                 00 00
       14001c508 48 8d 4d bc     LEA        RCX=>local_15c,[RBP + -0x44]
       14001c50c 45 33 c0        XOR        R8D,R8D
       14001c50f c7 44 24        MOV        dword ptr [RSP + local_1f8],0x3
                 20 03 00 
                 00 00
       14001c517 41 8d 51 03     LEA        EDX,[R9 + 0x3]
       14001c51b ff 95 28        CALL       qword ptr [RBP + CreateFileA]
                 01 00 00
       14001c521 4c 8b f8        MOV        R15,RAX
       14001c524 48 85 c0        TEST       RAX,RAX
       14001c527 0f 84 7d        JZ         LAB_14001c7aa
                 02 00 00

```

EDI, R8D, R9D are cleared, and then CreateFileA is called. The [function call for CreateFileA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) looks something like this
```
HANDLE CreateFileA(
  RBP-0x44       LPCSTR                lpFileName,
  FILE_ADD_FILE| FILE_WRITE_DATA DWORD dwDesiredAccess,
  0              DWORD                 dwShareMode,
  0              LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  OPEN_EXISTING  DWORD                 dwCreationDisposition,
  [in]           DWORD                 dwFlagsAndAttributes,
  [in, optional] HANDLE                hTemplateFile
);
```

# I am only human

I will be honest, After this, here be dragons as far as I am concerned. I was told the broad strokes of what the program does. Breaking down in detail what it does is beyond my skill level, and it is beyond Ghidra to display correctly. Or, if it can, I am not sure how to get Ghidra to cooperate. Throughout this whole binary, Ghidra has been fighting to incorrectly decompile the binary, and I have learned a lot on how to use Ghidra to prevent this from happening. But it's a slog.

It is not vital, and its only estimation and hearsay. After this point, there was a lot of interpreting, and Ghidra really struggles with Windows code (EDIT: Its better, but still a struggle), especially with the way this code loads certain areas of memory/files/code. Here is the broad strokes.

- The program will search for the first `.exe` file it can find.
- It does a ton of checking to see if it does things like: Is a PE file, is 64-bit, has valid and non-overlapping sections, and much more
- It will then copy itself, the whole `.text`/`.ivir` section over to the new infected file, and presumably move up the counter that is relied upon for decrypting the encrypted function.
- it will restart the program by shifting a bunch of stack and registers around so that it will essentially restart the program, but move the indicators down so it doesnt reinfect the same file, and keep going with the search.
- If it cannot find a `.exe` file, it will move up one level in the file directory to search from there.
If it does find a file, at some point, it will decrypt the encrypted function. which seems to be where the meat and potatoes are.

## Function Decryption

After all of this madness, there is something that the program does. Alllllll the way at the beginning of execution, it references a value in the file, and moves it to R14B

This is then compared against a multitude of values. if its 5 or above, it will just straight jump to execution of the encrypted function. if not, it will load keys based upon the value. the state we get it in is already set to 1, so our keys would look something like this
```python
keys = [  # Extracted from ghidra, and positioned based on compare statement relative to number of decrypts done. i.e. 0 loops done means 0th position.
    # 0x28c8aa0746a75909, # According to the counter, this has already been done, and program will not use this again
    0x6e2368b9c685770b,
    0xEB7FD64E061C1A3D,
    0xCB8FF2D53D7505A1,
    0xf1ef554206dce4d
]
```

The key is loaded into RBX, and the register is not touched at all throughout the entire execution of the program until one specific point. Thats the refresher, here is the code we finally arrive at.

```
       14001c736 4c 8b 64        MOV        R12,qword ptr [RSP + encfunc_offset]
                 24 68
       14001c73b 48 8b d7        MOV        RDX,RDI
							 decryptLoop                                     XREF[1]:     14001c760(j)  
       14001c73e 43 8b 4c        MOV        ECX,dword ptr [R9 + R8*0x1 + 0x2c]
                 01 2c
       14001c743 48 8b c3        MOV        RAX,RBX
       14001c746 49 03 ca        ADD        RCX,R10
       14001c749 49 03 cc        ADD        RCX,R12
       14001c74c 48 0f af        IMUL       RAX,qword ptr [RDX + RCX*0x1]
                 04 0a
       14001c751 48 89 04 0a     MOV        qword ptr [RDX + RCX*0x1],RAX
       14001c755 48 83 c2 08     ADD        RDX,0x8
       14001c759 48 81 fa        CMP        RDX,0x198
                 98 01 00 00
       14001c760 7c dc           JL         decryptLoop
```

To make this long story short, RDX is compared against a length that exactly matches the obfuscated bytes starting at 0x14001c7e4. And adds 8 to the value beforehand, matching the length of a quadword. if you see that the function offset is set to r12 above, you can see that it is taking the current key, and will multiply it by whatever bytes the program sees in the encrypted function.

So, we can actually recreate this functionality in python. see the code below.

```python
import struct

def decrypt_bytes(data, keys):
    for i in range(0, len(data), 8):
        quad_word = struct.unpack_from('<Q', data, i)[0]
        for key in keys:
            quad_word = (quad_word * key) & 0xFFFFFFFFFFFFFFFF  # Ensure it stays a 64-bit value
        struct.pack_into('<Q', data, i, quad_word)
    return data

with open("HELLO_WORLD_INFECTED_!!!.exe", "rb") as x:
    file = bytearray(x.read())  # Convert the file content to a bytearray

header_offset = 0x3c00  # Discovered via comparison of ghidra offset, and python offset

keys = [  # Extracted from ghidra, and positioned based on compare statement relative to number of decrypts done. i.e. 0 loops done means 0th position.
    # 0x28c8aa0746a75909, # According to the counter, this has already been done, and program will not use this again
    0x6e2368b9c685770b,
    0xEB7FD64E061C1A3D,
    0xCB8FF2D53D7505A1,
    0xf1ef554206dce4d
]

function_offset = 0x1c7e4 - header_offset  # Extracted from ghidra
length_func = 0x198  # Extracted from ghidra
encfunc_data = file[function_offset:function_offset + length_func]
encfunc_data = bytearray(encfunc_data)  # Convert to bytearray for mutability

print(encfunc_data)
decrypted_data = decrypt_bytes(encfunc_data, keys)

file[function_offset:function_offset + length_func] = decrypted_data

print(decrypted_data)

with open("HELLO_WORLD_INFECTED_!!!_decrypted.exe", "wb") as x:
    x.write(file)
```

There is a good sign immediately after executing this program.
```
...UWATAVAWH...
```

This is a variant of a function prologue, where it pushes a bunch of registers to the stack. 

source 1:
https://unix4lyfe.org/awavauatush/
source 2:
https://youtube.com/shorts/QVPMjbYbiQQ

Anyways, lets look at the decrypted function, with confidence that it should be correct.

So, doing so will get a function that looks very similar, but is honestly too long to capture in one block. so lets look at some of the repeated code.

```asm
       14001c808 33 d2           XOR        EDX,EDX
       14001c80a 48 8d 4c        LEA        RCX=>local_138,[RSP + 0x40]
                 24 40
       14001c80f e8 08 f8        CALL       strLookup_14001c01c                              char * strLookup_14001c01c(char 
                 ff ff
       14001c814 48 8b d0        MOV        RDX,RAX
       14001c817 48 8b cb        MOV        RCX,RBX
       14001c81a ff d6           CALL       RSI
```
this code calls a similar but different string lookup function, and calls RSI. crawling back, this RSI is initially filled by whatever is in RDX, which looking at what calls this function, is the exact same `GetProcAddress` we handled in the main code. So, lets grab and correct the source for this new string lookup function.

```c

char * strLookup_14001c01c(char *param_1,int param_2)

{
  char *pcVar1;
  
  pcVar1 = param_1;
  if (param_2 == 0) {
    strcpy(param_1, "LoadLibraryA");
  }
  else if (param_2 == 1) {
    strcpy(param_1, "user32.dll");;
  }
  else if (param_2 == 2) {
    strcpy(param_1, "MessageBoxA");
  }
  else if (param_2 == 3) {
    strcpy(param_1, "Correct!");
  }
  else if (param_2 == 4) {
    strcpy(param_1, "MESSAGEBOX");
  }
  else if (param_2 == 0xb) {
    strcpy(param_1, "FreeLibrary");
  }
  else if (param_2 == 0x10) {
    strcpy(param_1, "GetUserNameA");
  }
  else {
    pcVar1 = (char *)0x0;
    if (param_2 == 0x11) {
      strcpy(param_1, "Advapi32.dll");
      pcVar1 = param_1;
    }
  }
  return pcVar1;
}
```

This is different, `Correct!` seems to hint something relating to the flag, so that is encouraging.

Ghidra sort of fails us here, but the rough code looks something like this
```c
void decrypted_14001c7e4(HMODULE param_1,GetProcAddress *GetProcAddress)

{ 
  strLoadLibraryA = strLookup_14001c01c(local_138,0);
  LoadLibraryA_func = (LoadLibraryA *)(*GetProcAddress)(param_1,strLoadLibraryA);
  strFreeLibrary = strLookup_14001c01c(local_138,0xb);
  FreeLibrary_func = (FreeLibrary *)(*GetProcAddress)(param_1,strFreeLibrary);
  struser32.dll = strLookup_14001c01c(local_138,1);
  hModule_user32.dll = (*LoadLibraryA_func)(struser32.dll);
  strMessageBoxA = strLookup_14001c01c(local_138,2);
  MessageBoxA_func = (MessageBoxA *)(*GetProcAddress)(hModule_user32.dll,strMessageBoxA);
  strAdvapi32.dll = strLookup_14001c01c(local_138,0x11);
  hModule_Advapi32.dll = (*LoadLibraryA_func)(strAdvapi32.dll);
  strGetUserNameA = strLookup_14001c01c(local_138,0x10);
  GetUserNameA_func = (GetUserNameA *)(*GetProcAddress)(hModule_Advapi32.dll,strGetUserNameA);
  local_res8[0] = 0x100;
  (*GetUserNameA_func)(local_138,local_res8);
  ...
}


```

So, this seems to be setting up multiple libraries, and getting the functions from them, specifically `GetUserNameA` and `MessageBoxA`. 

The actual function calls aside from getting the functions from the requisite libraries, is `GetUserNameA`. Looking at the reference, the first parameter is a buffer, and the second parameter will specify the size of the buffer, in this case, 256 characters. It is also altered, so when returned, it will send back the amount of bytes read in. 

Source: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getusernamea

Then, if the string obtained from `GetUserNameA` is the right length, (25), the program will load a string into memory. We will get back to what that string is.

The program will compare the two obtained strings as seen in the box below.
```
                             cmpLoop                                         XREF[1]:     14001c914(j)  
       14001c901 8a 44 0c 20     MOV        AL,byte ptr [RSP + RCX*0x1 + local_158[1]]
       14001c905 38 44 0c 40     CMP        byte ptr [RSP + RCX*0x1 + local_138[1]],AL
       14001c909 75 0b           JNZ        notEqual
       14001c90b ff c2           INC        EDX
       14001c90d 48 ff c1        INC        RCX
       14001c910 48 83 f9 19     CMP        RCX,0x19
       14001c914 7c eb           JL         cmpLoop

```

This compares the strings, byte by byte. 

Afterwards, if the function does succeed in comparing the two values, it will make two calls to the `strLookup` again, and make the following call to `MessageBoxA` loaded earlier in the program. 

source: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa

```
int MessageBoxA(
  NULL           HWND   hWnd,
  "Correct!"     LPCSTR lpText,
  "MESSAGEBOX"   LPCSTR lpCaption,
  MB_OK          UINT   uType
);
```
In this case, null for `hWnd` just means its not associated to an owner window, and `MB_OK` has an OK button on the window. 

So, this program should pop up a box that says "Correct" if the username matches to the loaded string. Otherwise, it will not pop up anything, and close down the program.

The last thing in this function is two calls to `FreeLibrary`, to stop the program using the two loaded libraries previously in the function, and then a bunch of stack popping epilogue. 

So... what is this mystery string that is being compared? The flag!

[https://www.hackthebox.com/achievement/challenge/158887/300]
