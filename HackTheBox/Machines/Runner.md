HTB Machine

Runner starts off as always, with a scan

```nmap
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http        nginx 1.18.0 (Ubuntu)
|_http-title: Runner - CI/CD Specialists
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
8000/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Visiting the site, we can see its a simple landing page. but if we fuzz the subdirectories with
```
wfuzz -c -Z -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://runner.htb/ -H "Host: FUZZ.runner.htb" --hw 10
```

we can see theres a subdirectory called `teamcity`. visiting this site, we are met with a login page, but this very convienently also comes with a version
```
Version 2023.05.3 (build 129390)
```

googling this with teamcity gets us the cve.

[CVE-2023-42793](https://blog.jetbrains.com/teamcity/2023/10/cve-2023-42793-vulnerability-in-teamcity-update/)

Looking around for POCs, there are multiple. [example 1](https://github.com/H454NSec/CVE-2023-42793/blob/main/CVE-2023-42793.py) [example 2](https://github.com/Zenmovie/CVE-2023-42793)

however, I found that, for the purposes of getting to user, metasploit had a module that will do this for you, and give you a shell. `multi/http/jetbrains_teamcity_rce_cve_2023_42793` will give you access, so long as you modify settings appropriate to metasploit.

once you do, run linpeas on the target (which is a docker container on the target), and you will find an rsa key in there. Or by doing a find on the box, you can also find this key. And that is user.

However, we are not done with teamcity. if you read through linpeas, you will see references to something called backup. The links above will give you a login, unlike the metasploit module, and if you use this login, go to the admin panel, and look at the backup server administration tool, you can back up the teamcity instance, and this includes all of the sensitive data on the database. like the other user matthew.

downloading the `TeamCity_Backup_[timestamp].zip` will give you a database dump. looking at the users file, you will see hashes for the user you made, the admin, and matthew. cracking that by identifying the hash with `haiti` and cracking it with `hashcat` will give you matthew's password, but for what?

well, looking at `/etc/hosts` in the target, we can see another site!
```
john@runner:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 runner runner.htb teamcity.runner.htb portainer-administration.runner.htb
```

Alright, lets check this new one out!

a log in screen. lets use the password we recently obtained. That worked!. we are in a docker container web ui.

After a bit of poking, it seems we can create our own container, volume, and theres an image we can pull from that has ubuntu. so we need to mount our own volume, so that we share volumes with the host machine!

following [this guide](https://docs.portainer.io/user/docker/volumes/add#adding-a-tmpfs-volume), but deviating a bit, we enter in the new values of 
```
type : local
o : bind
device : /
```

Then, creating a new container, we make two alterations. In the "Command & Logging" section, we click the radial "Interactive & TTY", and move to volumes to add our created volume to `/rootfs` so we dont get confused as to wheres the host directory and whats the container directory.

Then, simply read anything you like from `/rootfs/root` and you should be golden. There is a private key there, but you can also just read `root.txt`.

https://www.hackthebox.com/achievement/machine/158887/598