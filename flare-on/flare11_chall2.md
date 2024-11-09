Flare-On 11 <br>By DisplayGFX <br>Challenge 2: checksum
===

Challenge Description:
```
We recently came across a silly executable that appears benign. It just asks us to do some math... From the strings found in the sample, we suspect there are more to the sample than what we are seeing. Please investigate and let us know what you find!
```

This one only has 1 file, `checksum.exe`

Opening this up in Ghidra shows that it is a Go binary. Thankfully, Ghidra handles that quite well these days.

If you execute the program, this is what you will see.

```
Check sum: 9590 + 4258 = 13848
Good math!!!
------------------------------
Check sum: 8316 + 6909 = 15225
Good math!!!
------------------------------
Check sum: 5453 + 7186 = 12639
Good math!!!
------------------------------
Checksum: 
```
Then, after giving the program a string, it prints out `Maybe it's time to analyze the binary! ;)`

And looking at `main.main`, you will see similar behavior. However, you will also see 2 functions associated with `main`. `a` and `b`. `b` just seems to be a sort of error handler. However, `a` seems different. Before analyzing, here is where `main.a` is used.
```c
	if (cVar2 == '\0') {
	  bVar3 = false;
	}
	else {
	  bVar3 = main.a(*inputString);
	}
}
else {
	bVar3 = false;
}
if (bVar3 == false) {
	local_88 = &string___internal/abi.Type;
	psStack_80 = &gostr_Maybe_it's_time_to_analyze_the_b;
	w_01.data = os.Stdout;
	w_01.tab = &*os.File__implements__io.Writer___runtime.itab;
	a_03.len = 1;
	a_03.array = (interface_{} *)&local_88;
	a_03.cap = 1;
	fmt::fmt.Fprintln(w_01,a_03);
}
```

This clearly is used to check some sort of string, and I made the assumption of the input string.

## Decrypting `main.a`

Looking at `main.a`,  it seems pretty simple. Inside a while loop, theres a `memequals` call that is used for the return.
```c
      if (sVar5.len == 0x58) {
        uVar1 = runtime::runtime.memequal(sVar5.str, "cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA==",0x58);
      }
      else {
        uVar1 = 0;
      }
      return (bool)uVar1;
```

And that string is clearly base64, also proven by the `encoding/base64::encoding/base64.(*Encoding).EncodeToString` call. It is a while loop, and theres only one more bit of code left.
```c
uVar3 = iVar4 + (iVar4 / 0xb + (iVar4 >> 0x3f)) * -0xb;
if (10 < uVar3) break;
[Var6.array[iVar4] = *(byte *)((int)puVar2 + iVar4) ^ (&DAT_004c8035)[uVar3];
iVar4 = iVar4 + 1;
```

Jumping to this location highlighted by `DAT_...` gets the string `FlareOn2024`

With this context, you are able to figure out that the base64 string is XORed with the key of the string we just found. Running the script below gets you back all ascii characters.

```python
import base64

main_a = 'cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA=='
xor_key = 'FlareOn2024'.encode()

bytes_main_a = base64.b64decode(main_a)
idx = 0
print("XORed Key:",end='')
for b in bytes_main_a:
    print(chr(b^xor_key[idx%0xb]),end='')
    idx += 1
```

The string you get back is `7fd7dd1d0e959f74c133c13abb740b9faa61ab06bd0ecd177645e93b1e3825dd`, giving that to the program will cause it to print `Noice!!`, and exit.

However, wheres the flag? Well, returning to `main.main`, after it passes the check in `main.a`, it runs the following code. (altered from ghidra to be readable)
```c
sVar10 = runtime::runtime.concatstring2(os::os.UserCacheDir(),"\\REAL_FLAREON_FLAG.JPG");
[Var13.len = local_180;
[Var13.array = (uint8 *)local_b0;
[Var13.cap = local_178;
eVar11 = os::os.WriteFile(sVar10,[Var13,0x1a4);
local_98 = &string___internal/abi.Type;
psStack_90 = &gostr_Noice!!;
w_02.data = os.Stdout;
w_02.tab = &*os.File__implements__io.Writer___runtime.itab;
a_04.len = 1;
a_04.array = (interface_{} *)&local_98;
a_04.cap = 1;
fmt::fmt.Fprintln(w_02,a_04);
```

While there is more to dissect in the EXE (for instance, I saw ChaCha20Poly1305, presumably for decrypting), to get the flag, all you need to do is to search for your cache directory, and that should get you the file. For me, it was `C:\Users\displaygfx\AppData\Local`.

Looking at the image will get you the flag

`Th3_M4tH_Do_b3_mAth1ng@flare-on.com`

Oh, and for the curious, where does the string we got come from. Well, it looks like a sha256 hash, so if you hash `REAL_FLAREON_FLAG.JPG`, it turns out that its exactly that, the hash of the flag.

```
$ cat checksum_image 7fd7dd1d0e959f74c133c13abb740b9faa61ab06bd0ecd177645e93b1e3825dd REAL_FLAREON_FLAG.JPG
$ sha256sum -c checksum_image   
REAL_FLAREON_FLAG.JPG: OK
```