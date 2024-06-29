HTB Challenge
## Initial Enumeration

Looking at the challenge, there is an apk we can dig into.

Open it up in jadx and unpack it in apktool.

![waiting_1.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/img/waiting_1.png)
It seems that, through many debug measures, jadx has a very hard time interpreting the code back to java. This is the SecretActivity library. So, in this case, you want to change it to simple on the toolbar below.

![waiting_2.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/img/waiting_2.png)

If you do that, it looks much better. We can see in this picture that it calls a functio from the `Secrets` class. Lets take a look at that

![waiting_3.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/img/waiting_3.png)

This will load a library called "secrets", so we need to examine that library. but before we do, a note on the other libraries.

There are 2 seperate anti-debugging measures/libraries.

there is `b.a.a.a` class, which will kill the box if it detects debugging measures. I used this java function to decode it.
```java
class HelloWorld {
    public static void main(String[] args) {
        String value = "\ue0a9\ue0b3\ue0b0\ue0e7\ue0f7\ue0fb\ue0fd\ue0f1\ue0c9\ue0f2\ue0ff\ue0f7\ue0ff\ue0eb\ue0e9\ue0ef\ue0e7\ue0f0\ue0bd";
        System.out.println(m3809a(value));
    }
    
        /* renamed from: a */
    public static String m3809a(String str) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            char charAt = str.charAt(i);
            sb.append((char) ((charAt ^ 57490 ^ (i % 65535))));
        }
        return sb.toString();
    }
}
```

There is also `utils.a` which has 3 encoded strings which imply that it will kill the app if it detects abd (an android debugging tool) or others. I used this java to deobfuscate the strings
```java
public static String m3835a(String str) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            sb.append((char) ((str.charAt(i) ^ 47191) ^ (i % 65535)));
        }
        return sb.toString();
    }
```

Now, lets take a look at `libsecrets.so`. To get at this, simply use `apktool d [your file].apk` to extract.

![waiting_4.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/img/waiting_4.png)

Open it in ghidra and look at the function called `getdxXEPMNe` and .... woah, thats a lot of array storage. Double click the area its taking from and you will see....

![waiting_5.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/img/waiting_5.png)

A bunch of ... one character strings. Convert them as such. which can get a little tedious, so a small trick is to hit `T` to change the data type of what you have currently selected, and hit `Y` to change the data type of the selected area to the last one you set.


![waiting_6.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/img/waiting_6.png)

Once you are done, it should look something like this.

Now, lets take a look at the function again.

![waiting_7.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/img/waiting_7.png)

Oh no, it seems to just be pointing the address. But, if you change the type, to an array of char \*, it should look more comprehensible.

![waiting_8.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/img/waiting_8.png)
This looks more like it. Doing it to the junk below almost gets something, but...

![waiting_9.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/img/waiting_9.png)
It looks incomplete. To complete this, we need to edit the size of the array. You can edit it in the decompile view, or you can edit it in the stack frame.

To briefly describe editing the stack frame, right click the top of the function, where all of the parameters are defined, and go to `Function->Edit Stack Frame...`, and from there, you would manually erase any data that is in the way. This can be very handy if you defined something beforehand, and it seems to have interfered with your ability to define a data type in the program.

So, having done that, now you can look at the code below... and its complicated.

Long story short, I had a very hard think about this, but essentially it will cycle through the two arrays we just manipulated, and XOR them together, and grow a string, over 48 cycles. so, if you start to XOR the first three letters
$0 \oplus x = H$
$8\oplus l= T$
$n \oplus , =  B$

So, if you do them all together, like so in python

```python
encoded_data = ["0", "8", "n", "8",[snip]"V"]
key_data = ["x", "l", ",", "C",[snip]"+"]  # Fill this with actual key values

decoded_string = ''.join(chr(ord(e) ^ ord(k)) for e, k in zip(encoded_data, key_data))
print(decoded_string)
```

you get the flag!

https://www.hackthebox.com/achievement/challenge/158887/454