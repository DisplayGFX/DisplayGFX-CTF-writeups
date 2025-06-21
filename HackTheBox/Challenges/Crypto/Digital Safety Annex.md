Digital Safety Annex
===

HTB Crypto Challenge

By DisplayGFX
___
Description:
```
Here at D.S.A we store all your super secret information in a secure vault until you provide us with proof you are who you say you are. We even use SHA256 instead of the weak SHA1! We are so confident, we invite all who wish to show us otherwise!
```

## Initial Enumeration

In this challenge, we have a server to connect to, and a `server.py`. 

So lets examine the python file to see anything interesting.

First thing to note is a "Test User Log" function within the user space

```python
inp = input("[+] Test user log (y/n) : ")
if (inp == 'y'):
	if annex.users['Admin'].login():
		print(f'\n{annex.user_log}')
```

And luckily, the admin password is avaiable in the source.
```python
def main():
    annex = Annex()
    annex.create_account("Admin", "5up3r_53cur3_P45sw0r6")
    annex.create_account("ElGamalSux", HTB_PASSWD)
```

Getting this log results in getting a bunch of  numbers, in an array.

```python
[(([snip], [snip]), 'a0aad39c9280260016dabaed8ca0c16d812ed8f2ccaa79eed07908f6bc74fb48'),
 (([snip], [snip]), 'b61c744b656adfca5049503c898073fefce49413e072505541e78460c02345ac'), 
 (([snip], [snip]), '625e8f4530e14927bd3095b35917e127a056517ba11fa7570deae5485a1a8503'), 
 (([snip], [snip]), '0e9722da720ecebce84ce77efa3f047e7a9b1c1fb11264be7d5cc1adbb8a73a5'), 
 (([snip], [snip]), '36f6e72c03df0167409761fa929d4574b13a7d513a903a8c49193836c0cb34cd'),
 (([snip], [snip]), 'e20824d197269d9df0949caf37c7df2676ffc9e6b26bf3fd6e34bcb872651445')]
```

Lets look at where and how the logs are stored...
```python
class Annex:
	...
    def log_info(self, account, msg, h, sig):
        _id = account.stored_msgs
        if account.username not in self.vault.keys():
            self.vault[account.username] = []
        
        self.vault[account.username].append((h, msg, (str(sig[0]), str(sig[1]))))
        self.user_log.append((sig, h))
        account.stored_msgs += 1
        
    def sign(self, username, message, password=""):
        account = self.users[username]
        ...
        msg = message.encode()
        h = sha256(msg).hexdigest()
        
        r, s = self.dsa.sign(h, account.k_max)
        
        self.log_info(account, msg, h, (r, s))
```

From this source, we can see that the message is hashed with sha256, and stored with the `r` and `s`. Which means, we should be able to deduce what message is what from the sha256 hashes stored so far. Lets write some python code to store the signing done so far.

```python
print((sha256("DSA is a way better algorithm".encode()).hexdigest()))
print((sha256("Testing signing feature".encode()).hexdigest()))
print((sha256("I doubt anyone could beat it".encode()).hexdigest()))
print((sha256("I should display the user log and make sure its working".encode()).hexdigest()))
print((sha256("To prove it, I'm going to upload my most precious item! No one but me will be able to get it!".encode()).hexdigest()))
```

And then match it to the hashes retrieved from the logs.

```python
[(([snip], [snip]), 'a0aad39c9280260016dabaed8ca0c16d812ed8f2ccaa79eed07908f6bc74fb48'), #"DSA is a way better algorithm"
 (([snip], [snip]), 'b61c744b656adfca5049503c898073fefce49413e072505541e78460c02345ac'), #"Testing signing feature"
 (([snip], [snip]), '625e8f4530e14927bd3095b35917e127a056517ba11fa7570deae5485a1a8503'), #"I doubt anyone could beat it"
 (([snip], [snip]), '0e9722da720ecebce84ce77efa3f047e7a9b1c1fb11264be7d5cc1adbb8a73a5'), #"I should display the user log and make sure its working"
 (([snip], [snip]), '36f6e72c03df0167409761fa929d4574b13a7d513a903a8c49193836c0cb34cd'), #"To prove it, I'm going to upload my most precious item! No one but me will be able to get it!"
 (([snip], [snip]), 'e20824d197269d9df0949caf37c7df2676ffc9e6b26bf3fd6e34bcb872651445')]
```

From here, we can see that there's one hash that isnt matched up, this must be the flag.

With the `r` and `s`, we can find the rest of the information we need.

## Exploitation and Bruteforcing

To take a step back, lets look at how we can get the flag in the first place.

```python
elif user_inp == '3':
	uname = input("\nPlease enter the username who stored the message : ")
	...
	req_id = input("\nPlease enter the message's request id: ")
	...
	if uname == account_username:
	...
	else:
		k = input("\nPlease enter the message's nonce value : ")
		...
		x = input("\n[+] Please enter the private key: ")
		...
		annex.download(int(x), int(k), int(req_id), uname)
...
def download(self, priv, nonce, req_id, username):
	...
	h, m, sig = self.vault[username][req_id]
	
	p, q, g = self.dsa.get_public_params()

	rp = pow(g, nonce, p) % q
	sp = (pow(nonce, -1, q) * (int(h, 16) + priv * rp)) % q

	new_sig = (str(rp), str(sp))

	if new_sig == sig:
		print(f"[+] Here is your super secret message: {m}")
	else:
		print(f"[!] Invalid private key or nonce value! This attempt has been recorded!")
```

If we provide the right private key, and the right nonce, the program will print back the original message.

But where are these? well, if you look to where it generates `r` and `s`, that will give you an idea what they are.
```python
class DSA:
...
	self.k_min = 65500
...
    def sign(self, h, k_max):
        k = random.randint(self.k_min, k_max)
        r = pow(self.g, k, self.p) % self.q
        s = (pow(k, -1, self.q) * (int(h, 16) + self.x * r)) % self.q
        return (r, s)
... #elsewhere in the program
	self.k_max = int(len(self.username) ** 6)
	if self.k_max < 65536:
		self.k_max += 1000000
```

There is the `r` and `s`. And there are 2 other values. `k`, which is generated every time the function is ran, this must be the nonce they mean. and `self.x`, which is constant for the lifetime of the program. Because we know that `k_max` is based on the username length, and `k_min` is a fixed value, we have a range of what `k` can be. And with the username `ElGamalSux` being 10 characters, its only up to 1 million. This is small enough to bruteforce!

Here is what the bruteforcing setup looks like

```python
for k in range(k_min, k_max + 1): 
	if k % 10000 == 0: 
		print(k//10000, "/100", sep='') 
	r_candidate = pow(g, k, p) % q 
	if r_candidate == r: 
		print(f"Found k for signature {idx}: k = {k}") 
		recovered_ks.append({'k': k, 'r': r, 's': s, 'h': h}) 
		found = True 
		break
...
# Recover x using the recovered k
for ks in recovered_ks:
    k = ks['k']
    r = ks['r']
    s = ks['s']
    h = ks['h']
    r_inv = inverse(r, q)
    x = ((s * k - h) * r_inv) % q
    print(f"\nRecovered private key x for k {k}: {x}") # these should all be the same value
```

For any given set of signatures, hashes, and public numbers, this essentially generates all of the candidate r values, and matches it to the real R value. When it finds a match for the nonce, any of the signatures can be used to extract the private key. 

Then, its just a matter of entering in the nonce and private key.

```
Welcome to the Digital Safety Annex!
We will keep your data safe so you don't have to worry!

[0] Create Account 
[1] Store Secret
[2] Verify Secret
[3] Download Secret
[4] Developer Note
[5] Exit

[+] Option >3
Please enter the username who stored the message : ElGamalSux
Please enter the message's request id: 3
Please enter the message's nonce value : 190057
[+] Please enter the private key: 5638232191613917890308330614433523284263706330923823380517844589408
[+] Here is your super secret message: b'HTB{flag:)}'
```

[https://www.hackthebox.com/achievement/challenge/158887/773]

## Appendix: Code used to solve the challenge

```python
from Crypto.Util.number import inverse, bytes_to_long
import re
import ast
import pwn

from multiprocessing import Pool, cpu_count

# pwn.context.log_level = "DEBUG"
conn = pwn.connect("94.237.54.42",39278)
conn.recvuntil("> ".encode())
conn.sendline("4".encode())
vals = conn.recvuntil("(y/n) :".encode())

p_match = re.search(r'p\s*=\s*(\d+)', vals.decode())
q_match = re.search(r'q\s*=\s*(\d+)', vals.decode())
g_match = re.search(r'g\s*=\s*(\d+)', vals.decode())

p = int(p_match.group(1)) if p_match else None
q = int(q_match.group(1)) if q_match else None
g = int(g_match.group(1)) if g_match else None

if p is None or q is None or g is None:
    print("val extract went wrong, exiting")
    exit()
conn.sendline("y".encode())
conn.recvuntil("password : ".encode())
conn.sendline("5up3r_53cur3_P45sw0r6".encode())
sigs = conn.recvuntil("Welcome to the Digital Safety Annex!".encode())[1:-38].decode()
data = ast.literal_eval(sigs)
signatures = []
signatures.append(data[0]) # 'DSA is a way better algorithm'
signatures.append(data[2]) # 'I doubt anyone could beat it'
signatures.append(data[4]) # "To prove it, I'm going to upload my most precious item! No one but me will be able to get it!" 
signatures.append(data[5]) # the flag

k_min = 65500
k_max = 1000000

def find_k(args):
    k_min, k_max, g, p, q, r_target = args
    for k in range(k_min, k_max + 1):
        if pow(g, k, p) % q == r_target:
            return k
    return None

def parallel_bruteforce(g, p, q, r, k_min, k_max):
    num_workers = cpu_count()
    chunk_size = (k_max - k_min) // num_workers
    ranges = [
        (k_min + i * chunk_size, k_min + (i + 1) * chunk_size - 1, g, p, q, r)
        for i in range(num_workers)
    ]
    ranges[-1] = (ranges[-1][0], k_max, g, p, q, r)  # Ensure last range ends at k_max

    with Pool(num_workers) as pool:
        results = pool.map(find_k, ranges)
    for result in results:
        if result is not None:
            return result
    return None

#bruteforce the k values
recovered_ks = []
for idx, sig in enumerate(signatures): 

    #Impatient
    if idx != 3:
        continue

    k_min = 65499
    r = sig[0][0]
    s = sig[0][1]
    h = int(sig[1], 16)

    print(f"\nAttempting to recover k for signature {idx}...")
    found = False
    k = parallel_bruteforce(g, p, q, r, k_min, k_max)
    if k:
        print(f"Found k for signature {idx}: k = {k}")
        recovered_ks.append({'k': k, 'r': r, 's': s, 'h': h})
    else:
        print(f"Failed to recover k for signature {idx}")
        exit()

# Recover x using the recovered k
for ks in recovered_ks:
    k = ks['k']
    r = ks['r']
    s = ks['s']
    h = ks['h']
    r_inv = inverse(r, q)
    x = ((s * k - h) * r_inv) % q
    print(f"\nRecovered private key x for k {k}: {x}") # these should all be the same value

conn.sendline("3".encode())
conn.recvuntil("message : ".encode())
conn.sendline("ElGamalSux".encode())
conn.recvuntil("id: ".encode())
conn.sendline("3".encode())
conn.recvuntil("value : ".encode())
conn.sendline(str(k).encode())
conn.recvuntil("key: ".encode())
conn.sendline(str(x).encode())
print("Flag:",conn.recvline()[41:-2].decode())

```