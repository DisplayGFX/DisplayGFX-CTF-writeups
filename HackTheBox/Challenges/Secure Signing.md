Secure Signing
===

HTB Challenge

By DisplayGFX
___
There seems to be only one file. but the challenge spawns an instance, so it seems we need to refine our attack on a local system first, then try our hand at the remote instance.

```python
WELCOME_MSG = """
Welcome to my Super Secure Signing service which uses unbreakable hash function.
We combine your Cipher with our secure key to make sure that it is more secure than it should be.
"""
```

```python
        if choice == 1:
            message = input("Enter your message: ").encode()
            hsh = H(xor(message, FLAG))
            print(f"Hash: {hsh.hex()}")
```

My my, it seems like they do exactly that. So, fun fact about xor, the mathmatical fact is that $0 \oplus X = X$ .

Due to a quirk in how zip works within the xor function seen below 
```python
def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])
```
it will only continue until the shortest variable is at its end. [see the python docs for proof](https://docs.python.org/3.11/library/functions.html#zip) So this means that it will only xor until the last character we give it. So as long as we have the hash for a string with only null bytes to the same length that we give it, we should have a way to confirm our guess is right.

Lets build a new solution to brute this. First, lets take out all of the UI elements and strip everything away to have a barebones version of the server to work with.

```python
from hashlib import sha256
FLAG = b"HTB{Helloworld!}"

def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])

def H(m):
    return sha256(m).digest()

message = b""
hsh = H(xor(message, FLAG))
```

next, lets try to first feed H a null byte
```python
nullhash = H(b"\0")
print(nullhash)
...
$ python3 attack.py   
b'n4\x0b\x9c\xff\xb3z\x98\x9c\xa5D\xe6\xbbx\n,x\x90\x1d?\xb378v\x85\x11\xa3\x06\x17\xaf\xa0\x1d'
```

Each null hash with a different length is different, so we do indeed need to rehash it every time. We know that the string begins with `H` so lets set our message to `H` as a try.
```python
message = b"H"
hsh = H(xor(message, FLAG))
nullhash = H(b"\0")
print(hsh)
print(nullhash)
$ python3 attack.py
b'n4\x0b\x9c\xff\xb3z\x98\x9c\xa5D\xe6\xbbx\n,x\x90\x1d?\xb378v\x85\x11\xa3\x06\x17\xaf\xa0\x1d'
b'n4\x0b\x9c\xff\xb3z\x98\x9c\xa5D\xe6\xbbx\n,x\x90\x1d?\xb378v\x85\x11\xa3\x06\x17\xaf\xa0\x1d'
```
our attack worked! Now to build it out. To really confirm it works, we need to get server running, and an automated attack to verify it works on our local host first.

turns out, pwntools can help us even in the event of local programs.

```python
from hashlib import sha256
import pwn
FLAG = b"HTB{Helloworld!}"

def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])

def H(m):
    return sha256(m).digest()

def connect_local():
    return pwn.process('python server.py', shell=True)
def connect_remote(host, port):
    return pwn.remote(host, port)

conn = connect_local()
# conn = connect_remote('remote.host', 1234)

def main():
    message = b"H"
    conn.recvuntil(b"> ")
    conn.sendline(b"1")
    conn.recvuntil(b"Enter your message: ")
    conn.sendline(message)
    hsh = H(xor(message, FLAG))
    nullhash = H(b"\0"*len(message))
    print(hsh.hex())
    print(nullhash.hex())
    response = conn.recvline_startswith(b"Hash: ")[6:]
    print(response.decode())

    conn.close()

if __name__ == "__main__":
    main()
```

This gets us three of the same hash. Now to build the bruteforce.

And with a little bruteforcing magic...!
```python
while bruteforcing:
	for guess in string.printable:
		conn.recvuntil(b"> ")
		conn.sendline(b"1")
		conn.recvuntil(b"Enter your message: ")
		nullhash = H(b"\0"*len(message+guess.encode())).hex()
		conn.sendline(message+guess.encode())
		response = conn.recvline_startswith(b"Hash: ")
		if nullhash.encode() == response[6:]:
			message += guess.encode()
			print(guess,sep="",end="")
			break
		if guess == string.printable[-1]:
			bruteforcing = False
			print("\n",sep="",end="")
```

Which gives us
```zsh
$ python3 attack.py
[+] Starting local process '/usr/bin/python3': pid 367489
HTB{Helloworld!}
[*] Stopped process '/usr/bin/python3' (pid 367489)
```
Why, it worked! now to test on the remote host!

Indeed, it works exactly the same!

https://www.hackthebox.com/achievement/challenge/158887/509