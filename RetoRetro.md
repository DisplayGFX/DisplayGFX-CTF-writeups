# Binary Patching is Fun!

Thanks to the help of @X41, @mytechnotalent (Kevin Thomas), and others who can ask for credit here if they want. 

writeup:

The program in question will need the libcrypto library. You can get this from `libssl1.1_1.1.1w-0+deb11u1_amd64.deb`. After installing this package, you can run the binary.

```
W3lc0m3 b4ck t0 th3 3ight13s !!!
Which console was the best one ever in the 80s?
Helloworld
You're not a truly retrogame lover...
```

Putting in some consoles will get you this.
```
W3lc0m3 b4ck t0 th3 3ight13s !!!
Which console was the best one ever in the 80s?
NES
Bah, if you say so...Good luck with this one:
[A tidal wave of hex characters]
```

Obviously, we need to reverse it. for this program, I will use ghidra.

Looking at the program in ghidra, it doesnt seem like there is a good way to figure out the console. Theres checks for a few consoles, and it produces results as seen above. Theres specifically a check for Atari, but it exits out before even trying to read the rest of the string, let alone trying to process it.

```
W3lc0m3 b4ck t0 th3 3ight13s !!!
Which console was the best one ever in the 80s?
Atari over 9000
Getting warmer!!
```

Looking at the rest of the program, it will hash the string, then check it against an obfuscated MD5 hash. This hash can be deobfuscated, but trying to brute force it will get you nowhere, even if you start with "Atari".

Looking further ahead, it seems to decrypt a blob with AES, and uses this with a cheat code to give you.... something in binary. Going back to the description...
```
Welcome back to the eighties! Some mediocre game programmer from the 80s has hidden an old ROM inside a modern executable. Can you find it and beat the game to gain the flag?
```

So this must be the rom they were talking about. This seems tough, as there doesnt seem to be an obvious way to guess the Console, even if we can.

However, theres a flaw. the AES Decrypt uses the hash of the console, not the console name, which is already present in the binary. verify this with ltrace. 

(with a modded binary for demonstration)
```bash
$ ltrace ./RetoRetro2 
...
puts("W3lc0m3 b4ck t0 th3 3ight13s !!!"...W3lc0m3 b4ck t0 th3 3ight13s !!!
)                  = 33
puts("Which console was the best one e"...Which console was the best one ever in the 80s?
)                  = 48
__isoc99_scanf(0x55aa2d44d0c0, 0x7fff62f75cd0, 0, 0x7fa7d7b15b00helloworld
) = 1
...
MD5(0x55aa2d5cbac0, 10, 0x55aa2d450150, 10)                  = 0x55aa2d450150
puts("Good job, Retrogamer!!"Good job, Retrogamer!!
)                               = 23
AES_set_decrypt_key(0x55aa2d450150, 128, 0x7fff62f74b60, 4112) = 0
```

Looking at [this page for MD5](https://www.openssl.org/docs/man1.1.1/man3/MD5.html) you will see that `0x55aa2d450150` is the address used by AES_Decrypt. But that isn't the string, but the MD5 hash, which is already the binary!

To find the actual hash, you need to look at the function called right after all of the string comparisons. From there, you can see a bunch of single character comparisons. if you reconstruct the hex of each of those characters, you end up with a valid md5 hash.

To get the program to actually decrypt, you need to modify a few instructions.
First, you need to pass the checks at  FUN_001014e3 (main). 
```
                    iVar3 = md5check();
                    if (iVar3 == 0) {
                      auStack_90[uVar4 * -2 + uVar5 * -2] = 0x101894;
                      puts("Good job, Retrogamer!!");
```
You need to turn this if check into ivar3 != 0. modify the check JNZ at 101785 to JZ

Next, to decrypt the blob correctly, you need to hijack a string, and change the pointer to the external call to that string. We will use the "Set decryption key in AES failed" below the AES command inside the AES decryption function.

Go to the string location in the program within ghidra, and in bytes view click the first button that looks like a pencil. edit in the md5 hash you just got, and end the hash with 00 to null terminate the string. watch out for the endianess, the MD5 hash needs to be backwards.

Now to patch the instruction, the one we care about is param_1 in ghidra. Which ghidra tells us is RAX. To patch this, we need to modify the instruction from `MOV RAX,qword ptr [RBP + -0x108]` in the main function which loads the pointer in the heap to the string to `LEA RAX, [`**controlled string address in the binary**`]` which points to our controlled string.

It seems that the code then alters a specific block of memory And then a block of checks afterwards.

if you look in ghidra, you will see
```

                      if ((((\*(char \*)((long)local_50 + 0x107) == 0x01) &&
                           (\*(char \*)((long)local_50 + 0x10f) == 0x02)) &&
                          (\*(char \*)((long)local_50 + 0x150) == 0x03)) &&
                         (\*(char \*)((long)local_50 + 0x155) == 0x04)) {
                        auStack_90\[uVar4 * -2 + uVar5 * -2\] = 0x101dd3;
                        puts("Well done!! Here\\'s your ROM; go play and get THE FLAG!!");
                      }
```

these are checking the bits that have been xor'd to see if its been done correctly. Ignore the strings and negative numbers, just reference the raw values in assembly view. Just before the bunch of assignments, you will see a function with two inputs.  within this function, it will reference cheat code you give it earlier in main. cross reference the if statements with the byte assignments, and you will get....
```
    (0xXX ^ X = 0x01) 
    (0xYY ^ Y = 0x02) 
    (0xZZ ^ Z = 0x03) 
    (0xAA ^ A = 0x04)
```
A property of XOR is that if you know the output and one of the two inputs, you can get the original key. In this case, you get ascii characters. using the fact that the function is rotating through this 4 character key, you can figure out the input. you will have to figure this step out yourself :P

This will get you the correct binary, the program should verify this. you will know its decrypted correctly if it the output has a huge block of `f` characters towards the end of the program.

Take this string, and feed it through xxd with the command `xxd -r -p out.txt output.bin` where you save the string as out.txt. You can play and analyze the rest of the challenge with a program called stella, which is essentially a debugger for Atari games.

However, the game is broken, and does not play correctly. Or if it does, its impossible to tell. Either way, if you look at the binary in stella, you will see

```
00000000
0█0000█0
0█0000█0
0█0000█0
0██████0
0██████0
0█0000█0
0█0000█0
0█0000█0
00000000
```

seems like each byte is used to print characters based on if the binary representation. You can see this extend all the way down, by looking ahead

```
 █    █ 
 █    █ 
 █    █ 
 ██████ 
 ██████ 
 █    █ 
 █    █ 
 █    █ 
        
████████
   ██   
   ██   
   ██   
   ██   
   ██   
   ██   
   ██   
        
███     
█  █    
█  █    
███     
█  █    
█  █    
█  █    
███     
        
  ██    
 █      
 █      
██      
██      
 █      
 █      
  ██    

[SNIP, not making this easy for script kiddies]

    ██  
      █ 
      █ 
      ██
      ██
      █ 
      █ 
    ██  
        
  ████  
 ██████ 
██ ██ ██
████████
███  ███
█ ████ █
 █    █ 
  ████  
```

Thus, I made this python script that will extract the bytes, starting at the address in stella, and printing it out.
```python
file_path = 'game.rom'  # Replace with the path to your ROM file

def process_rom(file_path):
    with open(file_path, 'rb') as file:
        rom_data = file.read(0x156)
    binary_representation = [format(byte, '08b').replace('1', '█').replace('0', ' ') for byte in rom_data]
    print_lines = ['        ']
    for i in range(0, len(binary_representation)-1, 9):
        character_lines = binary_representation[i:i+9]
        flip = character_lines[::-1]
        print_lines.extend(flip)

    print('\n'.join(print_lines))

def main():
    process_rom(file_path)

if __name__ == "__main__":
    main()
```

https://www.hackthebox.com/achievement/challenge/158887/448
