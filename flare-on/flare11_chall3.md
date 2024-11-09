Flare-On 11 <br>By DisplayGFX <br>Challenge 3: aray
===

Challenge Description:
```
And now for something completely different. I'm pretty sure you know how to write Yara rules, but can you reverse them?
```

This challenge also has 1 file, `aray.yara`. Reading through the file, its just one looooong rule
```yara
import "hash"

rule aray
{
    meta:
        description = "Matches on b7dc94ca98aa58dabb5404541c812db2"
    condition:
        filesize == 85 and hash.md5(0, filesize) == "b7dc94ca98aa58dabb5404541c812db2" and filesize ^ uint8(11) != 107 and uint8(55) & 128 == 0 and uint8(58) + 25 == 122 and uint8(7) & 128 == 0 and uint8(48) % 12 < 12 and uint8(17) > 31 and uint8(68) > ...
```

Now, admittedly, I did a bit of guessing when I was initially working this challenge, as I was not familiar with the ins and outs of yara. But here, I aim to solve this conclusively.
## Solving the Yara rule, with VSCode

Because the file is unworkably large and monolithic, lets break down the file into something more readable.
- First, select one `and` in VSCode. 
- Then, press `Ctrl+Shift+L`, which selects every instance in the file. 
- Then hit enter to replace all of the `and`s with a newline.
That's better, but each rule is unsorted.
- Select `uint8`
- Select every instance with `Ctrl+Shift+L`
- Use `Ctrl+L` to select every line with `uint8`.
- hold `shift` and hit the back arrow once to select just the line and not the following new line.
- Cut and paste elsewhere.

```
rule aray
{
    meta:
        description = "Matches on b7dc94ca98aa58dabb5404541c812db2"
    condition:
        filesize == 85 and
         hash.md5(0, filesize) == "b7dc94ca98aa58dabb5404541c812db2" and
         uint32(52) ^ 425706662 == 1495724241 and
         uint32(17) - 323157430 == 1412131772 and
         hash.crc32(8, 2) == 0x61089c5c and
         hash.crc32(34, 2) == 0x5888fc1b and
         uint32(59) ^ 512952669 == 1908304943 and
         uint32(28) - 419186860 == 959764852 and
         hash.crc32(63, 2) == 0x66715919 and
         hash.sha256(14, 2) == "403d5f23d149670348b147a15eeb7010914701a7e99aad2e43f90cfa0325c76f" and
         hash.sha256(56, 2) == "593f2d04aab251f60c9e4b8bbc1e05a34e920980ec08351a18459b2bc7dbf2f6" and
         uint32(66) ^ 310886682 == 849718389 and
         uint32(10) + 383041523 == 2448764514 and
         uint32(37) + 367943707 == 1228527996 and
         uint32(22) ^ 372102464 == 1879700858 and
         hash.md5(0, 2) == "89484b14b36a8d5329426a3d944d2983" and
         uint32(46) - 412326611 == 1503714457 and
         hash.crc32(78, 2) == 0x7cab8d64 and
         uint32(70) + 349203301 == 2034162376 and
         hash.md5(76, 2) == "f98ed07a4d5f50f7de1410d905f1477f" and
         uint32(80) - 473886976 == 69677856 and
         uint32(3) ^ 298697263 == 2108416586 and
         uint32(41) + 404880684 == 1699114335 and
         hash.md5(50, 2) == "657dae0913ee12be6fb2a6f687aae1c7" and
         hash.md5(32, 2) == "738a656e8e8ec272ca17cd51e12f558b" and
}

         filesize ^ uint8(11) != 107 and
         uint8(55) & 128 == 0 and
         uint8(58) + 25 == 122 and
         uint8(7) & 128 == 0 and
         uint8(48) % 12 < 12 and
         uint8(17) > 31 and.....
```

That's much better, but lets keep going a bit. Lets use the same technique to sort the block that is left over. Cut and paste the lines that contain `crc32`, `sha256`, `md5`, and you get...
```
filesize == 85 and
uint32(52) ^ 425706662 == 1495724241 and
uint32(17) - 323157430 == 1412131772 and
uint32(59) ^ 512952669 == 1908304943 and
uint32(28) - 419186860 == 959764852 and
uint32(66) ^ 310886682 == 849718389 and
uint32(10) + 383041523 == 2448764514 and
uint32(37) + 367943707 == 1228527996 and
uint32(22) ^ 372102464 == 1879700858 and
uint32(46) - 412326611 == 1503714457 and
uint32(70) + 349203301 == 2034162376 and
uint32(80) - 473886976 == 69677856 and
uint32(3) ^ 298697263 == 2108416586 and
uint32(41) + 404880684 == 1699114335 and
hash.sha256(14, 2) == "403d5f23d149670348b147a15eeb7010914701a7e99aad2e43f90cfa0325c76f" and
hash.sha256(56, 2) == "593f2d04aab251f60c9e4b8bbc1e05a34e920980ec08351a18459b2bc7dbf2f6" and
hash.md5(0, filesize) == "b7dc94ca98aa58dabb5404541c812db2" and
hash.md5(0, 2) == "89484b14b36a8d5329426a3d944d2983" and
hash.md5(76, 2) == "f98ed07a4d5f50f7de1410d905f1477f" and
hash.md5(50, 2) == "657dae0913ee12be6fb2a6f687aae1c7" and
hash.md5(32, 2) == "738a656e8e8ec272ca17cd51e12f558b" and
hash.crc32(8, 2) == 0x61089c5c and
hash.crc32(34, 2) == 0x5888fc1b and
hash.crc32(63, 2) == 0x66715919 and
hash.crc32(78, 2) == 0x7cab8d64 and
```

So, looking at reference for the [hash module in yara](https://yara.readthedocs.io/en/stable/modules/hash.html), these hashes (aside from one), all are taking 2 bytes. this is enough to bruteforce in python.

```python
import hashlib
import string
import zlib

solution = ['_']*85
charSolves =[('sha256', 14, "403d5f23d149670348b147a15eeb7010914701a7e99aad2e43f90cfa0325c76f"),
         ('sha256', 56, "593f2d04aab251f60c9e4b8bbc1e05a34e920980ec08351a18459b2bc7dbf2f6"),
         ('md5', 0, "89484b14b36a8d5329426a3d944d2983"),
         ('md5', 76, "f98ed07a4d5f50f7de1410d905f1477f"),
         ('md5', 50, "657dae0913ee12be6fb2a6f687aae1c7"),
         ('md5', 32, "738a656e8e8ec272ca17cd51e12f558b"),
         ('crc32', 8, 0x61089c5c),
         ('crc32', 34, 0x5888fc1b),
         ('crc32', 63, 0x66715919),
         ('crc32', 78, 0x7cab8d64),]

for a in string.printable:
    for b in string.printable:
        for x in charSolves:
            if x[0] == 'crc32':
                ex = zlib.crc32((a+b).encode())
            else:
                charhash = hashlib.new(x[0])
                charhash.update((a+b).encode())
                ex = charhash.hexdigest()
            if ex == x[2]:
                print(f"Pos {x[1]}:",a+b)
                solution[x[1]] = a
                solution[x[1]+1] = b

print(''.join(solution))
```

```
Pos 50: 3A
Pos 34: eA
Pos 56: fl
Pos 76: io
Pos 63: n.
Pos 78: n:
Pos 8: re
Pos 0: ru
Pos 32: ul
Pos 14:  s
ru______re____ s________________uleA______________3A____fl_____n.___________ion:_____
```

Well well, it seems like this is working out!

Next, lets look at the uint32 lines.

```
 uint32(52) ^ 425706662 == 1495724241 and
 uint32(17) - 323157430 == 1412131772 and
 uint32(59) ^ 512952669 == 1908304943 and
 uint32(28) - 419186860 == 959764852 and
 uint32(66) ^ 310886682 == 849718389 and
 uint32(10) + 383041523 == 2448764514 and
 uint32(37) + 367943707 == 1228527996 and
 uint32(22) ^ 372102464 == 1879700858 and
 uint32(46) - 412326611 == 1503714457 and
 uint32(70) + 349203301 == 2034162376 and
 uint32(80) - 473886976 == 69677856 and
 uint32(3) ^ 298697263 == 2108416586 and
 uint32(41) + 404880684 == 1699114335 and
```

These are simple add, subtract, and xor operations that can be undone. So lets do so again in python.

```python
int32Solves = [(52,'^', 425706662,1495724241),
        (17,'-', 323157430,1412131772),
        (59,'^', 512952669,1908304943),
        (28,'-', 419186860,959764852),
        (66,'^', 310886682,849718389),
        (10,'+', 383041523,2448764514),
        (37,'+', 367943707,1228527996),
        (22,'^', 372102464,1879700858),
        (46,'-', 412326611,1503714457),
        (70,'+', 349203301,2034162376),
        (80,'-', 473886976,69677856),
        (3,'^', 298697263,2108416586),
        (41,'+', 404880684,1699114335),]
for x in int32Solves:
    match x[1]:
        case '^':
            res = x[2]^x[3]
        case '-':
            res = x[3]+x[2]
        case '+':
            res = x[3]-x[2]
    res = bytes.fromhex(hex(res)[2:]).decode()
    print(f"Pos {x[0]}:\t {res}")
    solution[x[0]] = res[0]
    solution[x[0]+1] = res[1]
    solution[x[0]+2] = res[2]
    solution[x[0]+3] = res[3]
```


```
Pos 52:  @y4w
Pos 17:  gnir
Pos 59:  o-er
Pos 28:  R1" 
Pos 66:   "mo
Pos 10:  { no
Pos 37:  3Kya
Pos 22:  f$ :
Pos 46:  r4wl
Pos 70:  dnoc
Pos 80:   f$ 
Pos 3:   lf e
Pos 41:  M$p3
ru_lf e_re{ no s_gnir_f$ :__R1" uleA_3KyaM$p3_r4wl3A@y4wfl_o-ern._ "modnoc__ion: f$ _
```

One last step, it seems, and I think the flag will be revealed.

There are over 520 lines that contain `uint8`. So it might be better to pair down how many are needed to process. Not all of the lines can be useful, surely.

First,  lets look at one of the first lines that stands out, here.
```
filesize ^ uint8(11) != 107 and
```

The only thing this tells us is that one character cannot be a certain value. Lets extract all of the lines that have a `!=`. Use the same methodology as covered above. Next few line:

```
uint8(55) & 128 == 0 and
uint8(17) > 31 and
uint8(56) < 155 and
uint8(48) % 12 < 12 and
```

There doesnt seem to be anything useful. In fact, they are all useless. in their own way
- `& 128 == 0` will always be true if we assume that all characters are ascii, as ascii only goes to `0x7f`, or 7 bits. 128 is the eighth bit.
- `% X < X` is always the same number in these two locations, and is categorically always true, as the modulo, or the remainder result is always less than the number used
- `>` and `<` can technically be useful, if they were used in constraint solving. But without analyzing every statement, there doesn't seem to be any overlap.

Grabbing lines with `& 128`, `>`, `%`, `<` (in that order) will effectively sort, and extract the irrelevant characters. What is left are these lines.

```
uint8(58) + 25 == 122 and
uint8(36) + 4 == 72 and
uint8(27) ^ 21 == 40 and
uint8(65) - 29 == 70 and
uint8(45) ^ 9 == 104 and
uint8(74) + 11 == 116 and
uint8(75) - 30 == 86 and
uint8(2) + 11 == 119 and
uint8(7) - 15 == 82 and
uint8(21) - 21 == 94 and
uint8(16) ^ 7 == 115 and
uint8(26) - 7 == 25 and
uint8(84) + 3 == 128 and
```

Which can be tackled by the above code again.

```python
...
         (58, '+', 25, 122,),
         (36, '+', 4, 72,),
         (27, '^', 21, 40,),
         (65, '-', 29, 70,),
         (45, '^', 9, 104,),
         (74, '+', 11, 116,),
         (75, '-', 30, 86,),
         (2, '+', 11, 119,),
         (7, '-', 15, 82,),
         (21, '-', 21, 94,),
         (16, '^', 7, 115,),
         (26, '-', 7, 25,),
         (84, '+', 3, 128,),
        ]
for x in int32Solves:
    match x[1]:
        case '^':
            res = x[2]^x[3]
        case '-':
            res = x[3]+x[2]
        case '+':
            res = x[3]-x[2]

    res = bytes.fromhex(hex(res)[2:]).decode()
    print(f"Pos {x[0]}:\t {res}")
    if len(res) == 4:
        res=res[::-1]
        solution[x[0]] = res[0]
        solution[x[0]+1] = res[1]
        solution[x[0]+2] = res[2]
        solution[x[0]+3] = res[3]
    elif len(res) == 1:
        solution[x[0]] = res[0]

```

And this solves the challenge!
```
$ python brute.py
rule flareon { strings: $f = "1RuleADayK33p$Malw4r3Aw4y@flare-on.com" condition: $f }
```


as an interesting post solve note, `filesize ^ uint8(X) != Y` has a position for every single character. However, trying to undo the xor, no matter what size you try for `filesize`, it will always be garbage. I suspect the same is true for the useless boolean statements that were also pruned.
