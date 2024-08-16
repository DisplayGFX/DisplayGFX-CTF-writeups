HTB Challenge

Another crypto challenge, another python and output file.

## Enumeration
The description mentions a lost modulus with RSA. RSA uses $c = m^e \mod n$ to calculate the message. In this case, n should be the variable we are concerned for, where c is the ciphertext, m is the plaintext, and c is the public key. 

Lets run the program first, see what it outputs compared to `output.txt`, in place of the real flag, we can use `HTB{Helloworld!}`.

```python
Traceback (most recent call last):
  File "/home/kali/htb/challenge/crypto_lost_modulus/challenge.py", line 28, in <module>
    main()
  File "/home/kali/htb/challenge/crypto_lost_modulus/challenge.py", line 22, in main
    crypto = RSA()
             ^^^^^
  File "/home/kali/htb/challenge/crypto_lost_modulus/challenge.py", line 11, in __init__
    self.d = inverse(self.e, (self.p-1)*(self.q-1))
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/kali/.local/lib/python3.11/site-packages/Crypto/Util/number.py", line 139, in inverse
    return pow(u, -1, v)
           ^^^^^^^^^^^^^
ValueError: base is not invertible for the given modulus
```
Hmm, seems like we dont even get to that step.

```python
class RSA:
    def __init__(self):
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.e = 3
        self.n = self.p * self.q
        self.d = inverse(self.e, (self.p-1)*(self.q-1))
```
Line 7 seems to be the problem.

## Analysis of RSA and challenge.py

We have to assume that both p and q are missing. But e seems to be suspect in this transaction. If it hasn't been modified, that would imply the message has only been cubed. Meaning, if the modulus is big enough, the entire message would be smaller than $n$ . This means that no information would be destroyed by the modulo. This would bypass any value of $p$ and $q$ .

Because $p$ and also $q$ are 512 bits long, our message is likely to be vastly smaller than that. theoretically, $n$ should be about 1024 bits long, so long as our ciphertext is smaller than this (message raised to the $e$ power), it should be not affected by the modulo. We can actually determine that. If we assume $n$ is 1024 bits long, that means $n ≈ 2^{1024}$ approximately. so as long as $m^3 < n$ , we can assume our message is just cubed.

to solve this, we substitute $n$ with our assumed value. And take the log base 2 of both sides.
$log_2(m^3) < 1024$
$3*log_2(m) < 1024$ 
$log_2(m)<{1024}/3$ 

so our maximum bit length is `1024/3`, or around 341 bits. or in other words, as long as the flag is below around 42 bytes, we can just take the cube root of our encoded message. Have you seen a flag that long? I haven't.

## Solution

Lets try this, we shouldn't need to modify any code. Lets add this onto the end of the original code.
```python
    outputtxt = open('output.txt',"r").read()[6:]
    enc_flag = bytes.fromhex(outputtxt)
    flag = crypto.decrypt(enc_flag)
    print(flag.decode())
```

After a few tries of getting errors with incompatible key values, we do indeed get the flag.

https://www.hackthebox.com/achievement/challenge/158887/232