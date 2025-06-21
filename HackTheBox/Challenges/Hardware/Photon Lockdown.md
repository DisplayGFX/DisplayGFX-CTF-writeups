Photon Lockdown
===

HTB Hardware Challenge

By DisplayGFX
___
Description
```
We've located the adversary's location and must now secure access to their Optical Network Terminal to disable their internet connection. Fortunately, we've obtained a copy of the device's firmware, which is suspected to contain hardcoded credentials. Can you extract the password from it?
```

## Initial Enumeration

When unzipping, we see 3 files.
```zsh
$ ls
fwu_ver  hw_ver  rootfs
```
both `fwu_ver` and `hw_ver` are small and contain `3.0.5` and `X1` respectively. We can safely ignore them for now. `rootfs` however, is much larger, and using `binwalk`, it can show us why.

```zsh
$ binwalk rootfs 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Squashfs filesystem, little endian, version 4.0, compression:gzip, size: 10936182 bytes, 910 inodes, blocksize: 131072 bytes, created: 2023-10-01 07:02:43
```

It uses `squashfs` which basically is a compressed copy of an entire linux system, which we can unpack with `unsquashfs`, just a simple `unsquashfs rootfs` gets us the file system. The command will complain about not having superuser permission, but considering it could mess with the OS, I am fine with that. Using `ls` seems to show a traditional linux file system.

Lets do a lazy grep search with `grep -rn "HTB" *`. This should search through all of the files recursively, and print out where it found a match.

Oh look, we found a match! The rest seem to be binary files, but that matters not.
```zsh
$ grep -rn "HTB" *         
...
etc/config_default.xml:244:<Value Name="SUSER_PASSWORD" Value="HTB{[cmon]}"/>
...
```

https://www.hackthebox.com/achievement/challenge/158887/548