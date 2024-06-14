This one is super easy. After the usual setup, you'll see these files.

```bash
$ ls -laR      
.:
total 24
drwxr-xr-x  4 kali kali 4096 Feb 11 06:51 .
drwxr-xr-x 62 kali kali 4096 Feb 11 06:47 ..
drwxr-xr-x  2 kali kali 4096 Nov  6  2020 css
-rw-r--r--  1 kali kali   19 Nov  5  2020 dashboard.html
-rw-r--r--  1 kali kali  513 Nov  5  2020 index.html
drwxr-xr-x  2 kali kali 4096 Nov  6  2020 js

./css:
total 12
drwxr-xr-x 2 kali kali 4096 Nov  6  2020 .
drwxr-xr-x 4 kali kali 4096 Feb 11 06:51 ..
-rw-r--r-- 1 kali kali 1396 Nov  5  2020 style.css

./js:
total 16
drwxr-xr-x 2 kali kali 4096 Nov  6  2020 .
drwxr-xr-x 4 kali kali 4096 Feb 11 06:51 ..
-rw-r--r-- 1 kali kali 6588 Nov  6  2020 login.js
```

you can safely ignore style.css (taken straight from google afaik), and dashboard.html (a dummy flag). 

Reading index.html, there is a line: `<input type="button" value="Login" id="submit" onclick="validate()"/>` which calls javascript. The only javascript that is called in the login.js. 

Looking at the file shows that its obfuscated. 
```javascript
var _0x4e0b=['\x74\x6f\x53\x74\x72\x69\x6e\x67','\x75\x73\x65\x72\x6e\x61\x6d\x65','\x63\x6f\x6e\x73\x6f\x6c\x65','\x67\x65\x74\x45\x6c\x65\x6d\x65\x6e\x74\x42\x79\x49\x64','\x6c\x6f\x67','\x62\x69\x6e\x64','\x64\x69\x73\x61\x62\x6c\x65\x64','\x61\x70\x70\x6c\x79','\x61\x64\x6d\x69\x6e','\x70\x72\x6f\x74\x6f\x74\x79\x70\x65','\x7b\x7d\x2e\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72\x28\x22\x72\x65\x74\x75\x72\x6e\x20\x74\x68\x69\x73\x22\x29\x28\x20\x29','\x20\x61\x74\x74\x65\x6d\x70\x74\x3b','\x76\x61\x6c\x75\x65','\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72','\x59\x6f\x75\x20\x68\x61\x76\x65\x20\x6c\x65\x66\x74\x20','\x74\x72\x61\x63\x65','\x72\x65\x74\x75\x72\x6e\x20\x2f\x22\x20\x2b\x20\x74\x68\x69\x73\x20\x2b\x20\x22\x2f','\x74\x61\x62\x6c\x65','\x6c\x65\x6e\x67\x74\x68','\x5f\x5f\x70\x72\x6f\x74\x6f\x5f\x5f','\x65\x72\x72\x6f\x72','\x4c\x6f\x67\x69\x6e\x20\x73\x75\x63\x63\x65\x73\x73\x66\x75\x6c\x6c\x79']
[snip]
res=String['\x66\x72\x6f\x6d\x43\x68\x61\x72\x43\x6f\x64\x65'](0x48,0x54,[snip],0xa);
```

So, lets go to google, and find the first deobfuscator we can get our hands on. That one points out that a specific tool was used to obfuscate the javascript, Obfuscator.io. the link, https://obf-io.deobfuscate.io/, shows us enough to solve the challenge.

```javascript
...
var res = String.fromCharCode(0x48, 0x54, [snip], 0xa);
```

Very simply, run this in your javascript console, and you will see

```javascript
String.fromCharCode(0x48, 0x54,[snip], 0xa)
"HTB{f4k3_fl4g_f0r_t3st1ng}[\n]" 
```

Of course I wont give you the real flag here! go on, its easy!
https://www.hackthebox.com/achievement/challenge/158887/156