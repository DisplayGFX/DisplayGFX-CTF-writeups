Substandard Optimization
===
HTB Challenge

The Substandard program and the challenge appears deceptively simple. The challenge is to get  Ghidra to cooperate with the binary in disassembly and interpret the program correctly. The process only got harder to understand as the challenge continued.  
  
The description of the challenge seems to give a hint about solving it.  Here is the description:

>Tired of solving all those challenges? Sit back and let my brand new program just print the flag for you! It might be a little slow - after all, I only know one instruction!

## Initial Enumeration

In the provided binary, the main function enters an infinite loop calling `do_step` . The input is a reference to a huge blob of binary. Inside the function, it appears incredibly messy on first blush. Ghidra cannot handle the binary in its current state.

In the binary blob all of the values cleanly split among the 4 byte boundary. There are even markers that show the beginning and end of the binary program. In Ghidra, press `T` and cast this data as an int (4 byte) array to reflect this finding.
## do_step - Function Analysis

First thing the program does is to load the program array into a local variable. We know this is an `int` array, so retyping the function signature will clean the function up significantly.

Next, it will do a complicated operation. It loads in a QWORD, and then later on through following the variable assignment, the program will take out DWORD values from this QWORD. There are 2 DWORDS in a QWORD, so the way we resolve this issue is to make a UNION data type. 

A union data type allows for a variable to be interpreted in different ways while occupying the same memory space. As an example, you can have a union data type that is a series of rooms in sequence, or be interpreted as a house. Both technically use the same data and same size, but you can select a room without needing to process the rest of the data involved in getting the data from a house.

This union below will allow Ghidra to correctly decompile the assembly into C code thereby allowing for a more straightforward decomplication.

```c
union value_union {
    int64_t quadword;      // 64-bit integer
    struct {
        int32_t low;       // Lower 32 bits
        int32_t high;      // Upper 32 bits
    } doubleword;
};
```

While this is not perfect the data type will function in Ghidra.

The way I interpret things, now that we have the program correctly decompiling, it will check if the high or low value is exactly `-1`, and will print a character in the program or grab a character from the input to place in some value accordingly to the opposite value. If high is `-1`, then it uses the low value. If low is `-1`, then high is used.  In either case a counter is incremented by 3. 

This is an odd amount to be incrementing if you want to keep the 4 byte structure. And odder still is  the reference used to set that value. It comes from the stack which is not normal behavior. That section of the stack was explicitly set to zero just as the main program was initializing the int array. Therefore this is must be more than just a counter.

This indicates that the variable passed into the program is not a simple int array, it is a structured data type. Utilizing the earlier union data type we can create a structure in C for a counter and an array pointer in one object. However, that doesn't fully explain the apparent third value. I made a construct called `binstep`, which includes the value union discussed above, and also a third value that remedies this issue. 

See the below code for the structure of the object:

```c
struct turing {
    struct int[SIZE_OF_BLOB] *program;
    int32_t counter;
};

struct binstep {
    union value_union registers;
    int32_t Next;
};
```

By directly modifying the `do_step` function in Ghidra from the int array into Turing object and it uses a binstep object  which then makes the rest of the binary crystal clear. 

After implementing these types into the function itself, it should look something like this in Ghidra

```c
void do_step(turing *param_1){
   int char;
   binstep *instrPtr;
   int low;
   int high;
   int nextInstruction;
   int (*programPtr) [4542];
   
   programPtr = param_1->program;
   instrPtr = (binstep *)(*param_1->program + (uint)param_1->counter);
   nextInstruction = instrPtr->next;
   low = (instrPtr->registers).doublewords.low;
   high = (instrPtr->registers).doublewords.hi;
   if (low == -1) {
      char = getchar();
      (*programPtr)[high] = char;
      param_1->counter = param_1->counter + 3;
   }
   else if (high == -1) {
      putchar((*programPtr)[low]);
      param_1->counter = param_1->counter + 3;
   }
   else {
      (*programPtr)[high] = (*programPtr)[high] - (*programPtr)[low];
      if ((*programPtr)[high] < 1) {
         if (nextInstruction == -1) {
                               /* WARNING: Subroutine does not return */
            exit(0);
         }
         param_1->counter = nextInstruction;
      }
      else {
         param_1->counter = param_1->counter + 3;
      }
   }
   return;
}

```


For the rest, looking at the decompilation should be enough.  In the below graph you will see a description of the functioning of the program.
## do_step - Full Understanding and Recreation.

![FA map](https://github.com/DisplayGFX/DisplayGFX-CTF-writeups/blob/main/img/substandard_1.png)

The above graph is called a state diagram. This is a rough diagram, but all state diagrams are similar. The program starts at the `start` state. Each bubble represents a state and associated action with the arrows meaning the result of an action. The idea is to follow the path of the state diagram until it results in an exit.

So the program will iterate following this state diagram.  It goes value by value, subtracting the A location value from the B location value, and storing it in the B location. 

If any of the three values are negative it will go into a special state. Exiting, taking in, or putting out a character each time. 

Lastly if A or B is -1, or if the location of B is positive after the resultant value is stored, the program will increment the counter to the next set of values. If the location of B is negative it will set the value to the nextVar which is the third value in the Turing machine.

With this established it is simple to recreate the function in python.

```python
turingMachine = Turing(program)
def do_step():
    curStep = Binstep(turingMachine.program[turingMachine.counter], 
					  turingMachine.program[turingMachine.counter+1], 
						  turingMachine.program[turingMachine.counter+2])
    nextVar = curStep.Next
    a = curStep.reg_a
    b = curStep.reg_b
    if a == -1:
        print("Input required:")
        # Read a single character and store its ASCII value, mask allowing only the first byte to be edited
        turingMachine.program[b] = ord(input()[0]) & 0xFF + program[b] & 0xFFFFFF00  
        turingMachine.counter += 3
    elif b == -1:
	    # prints single char, mask ensuring
        print("Output:", chr(turingMachine.program[b] & 0xFF))  
        turingMachine.counter += 3
    else:
	    #subtracts the value at A from the value at B, stores result at B
        turingMachine.program[b] -= turingMachine.program[a]
        if turingMachine.program[b] < 1:
            if nextVar == -1:
                print("Exiting...")
                exit(0)
            turingMachine.counter = nextVar
        else:
            turingMachine.counter += 3
```

Recreating the function is simple. The real challenge is ..... ***O B S E R V A T I O N***.

## Visualizing the Turing Machine - ***O B S E R V A T I O N***

I have a personal philosophy about learning: the lower the cognitive burden the easier it is to learn. And in that spirit, I have made this program visualizing the operation of the Turing machine.

![visualization of the virtual machine in action](https://github.com/DisplayGFX/DisplayGFX-CTF-writeups/blob/main/img/substandard_2.png)

The red number is the index of the A location. The orange/yellow number is the index for the B location. The green number is the nextVar location that the program will jump to in case B location ends up being less than 1. And the purple number is the most recently changed value in the program. The code is at the end of this file, and stored seperately as .

With the power of observation, I shall decode this program!

## Analyzing the Program

There seems to be 3 segments in the code

Initial instruction:
There is an instruction that does nothing but jump to later in the program. It accesses its own value (zero) and subtracts itself from itself. This alters nothing and causes the counter to jump.

##### Block 1
It seems that the block after this instruction all contains printable text. Looking at it in the emulator I created it shows that every value is in the printable range of ascii.

![a bunch of ascii letters in emulator](https://github.com/DisplayGFX/DisplayGFX-CTF-writeups/blob/main/img/substandard_3.png)
##### Block 2
This block starts at 1203, right after the ascii block. It contains numbers that are way outside the range of  the program and the bytes don't correspond to any ascii. It ends with the value `1200` so there's a length to this block.

If you look at the distribution of the data, it is all tightly focused around the billions.

![graph of values charted](https://github.com/DisplayGFX/DisplayGFX-CTF-writeups/blob/main/img/substandard_4.png)

There doesn't seem to be a discernable pattern aside from the relatively tight grouping.

![scatterplot of values](https://github.com/DisplayGFX/DisplayGFX-CTF-writeups/blob/main/img/substandard_5.png)
##### Block 3

The third block appears to be a block of instructions. It all contains values that are pointing to within the program or just outside of it. So this should be where most of the execution take place.

## Levels of Observation and Abstraction

For this program it seems that for each observation and abstraction that I was able to verify the program got easier and easier to understand. Instead of a walkthrough of how the program inside the program functions, it would be a greater opportunity to show the abstractions, observations, and progress I made towards solving the challenge. These observations were obtained in three ways: 
- Observing the program as it runs.
- Looking at the execution of instructions in order.
- Treating the data values as a new kind of assembly and reading the instructions directly.

At the end of this document I provide the source code for those who want to see it in action themselves.

### Layer 0: Wait a Second, this is a Turing Machine!

Here you will see references to the the concept. But before starting on the layers of concepts below, lets make the implicit explicit: this program is very similar to the concept of a Turing machine. It takes in a bunch of ones and zeros, and uses a made up list in its programming to determine what happens next. The instruction list can be very lengthy for this operation but its one of the first conceptual computers. This was theorized by Alan Turing. If you want to learn more, [read the Wikipedia article.](https://en.wikipedia.org/wiki/Turing_machine) 

In short, the "tape" as it will now be referred to contains data, and will also contain "instructions" on what the machine should do next. The program here will operate on what the index location referred to by the second input is measured at.  If 1 or higher, the Turing machine moves to the next instruction. If negative 1 (in any cell) and the Turning machine does a special operation, then it moves to the next instruction. If the B value is less than 1 the program jumps to the index at the third input value.
### Layer 1: It Gets Stuck in a Loop, a Very Long Loop

If you observe the program it is obvious that it is changing values and is getting stuck in a loop. I built a tool to actually look at the execution of the instructions and allow you to find where this loop happens. There are roughly 300 instructions and then around instruction 301 it goes back to 2728 over and over whenever the Turning machine hits 2995. This must be where it gets stuck for a VERY long time. So long that I don't think there's a tool that could tell you what happens at the end. This too is a famous problem theorized by Alan Turing, where he mathematically proves that you cannot be certain when the program halts by simple mathematics of the inputs and how the program works alone.

Observation: If we want to really solve this challenge, we need to understand at least what this loop is doing, if not the whole program, to skip over the functionally infinite loop.

### Layer 2: There is Untouched Tape and Tape that is Constantly Changing

Watching the program memory in action you will soon notice that the program keeps referencing and modifying the end of the tape. Any tape above 4541 will be tape that is lighting up like a Christmas tree with changes. The odd thing is the program ends with value 4541 so what that program data is... I don't know! Other tape, between 4522 and 4541, is tape modified or read by the program. 

Observation: With the exception of very specific cases we will get to, the program refers to this area over and over. This must be some sort of temporary area which we will call "scratch" for now.  Also, the program has more tape than first imagined.

Action: to make the program more clear, lets mark the whole area as `scratch[offset from 4541]` for the area above 4540, and between 4522 and 4541, lets mark those as `int[offset from 4522]`.  And also, lets give data in Python that allows for the program to use more tape than just the program data. I ran into this problem much earlier, and had to fix it before even analyzing the program.

### Layer 3: Blocks of Program

Looking at the execution sequence, there are 3 distinct areas of code within the code block, ordered in terms of when in the program it is executed. 

- The first block starts from 4489, and goes for about 10 instructions.
- The second block starts at 3166, and goes for about another 190 instructions.
- The third block starts from the beginning of the code block at 2404 and then runs into the infinite loop.

A few observations we can take from this:

- Observation 1: the third block starts at 2404, not 2403. And the number at 2403 matches with the length of the encrypted block exactly. As far as I can see, there is nothing that changes this value. Maybe there are more instructions in the code block that specifically reference the ascii block?
- Observation 2: there are 3 blocks that cover most of the program tape space, splitting the blocks into these three chunks will help readability immensely.
- Observation 3: The first block in execution seems to be small enough to manually analyze.

Actions:
- Mark the location at 2403 as a constant. Lets call it `blocklen`
	- Then after additional investigation based on the same idea, the block starts at 1203, and there is a value in `int[8]` that will point to the exact start of the block. As far as I know so far, this value does not change. Lets name it `blockloc`.
-  Break up the code block into areas along the lines highlighted above. This aids in readability, and this is the goal.
- Next steps are to look at the first block of code and trace the program to understand what it is doing.

### Layer 4: No Jumping Allowed in the Pool (unless sometimes...)

A quick observation based on just watching the 3rd value of the Turing machine before going further.

Observation: - 
- The third value in the Turing machine is almost always set to the next instruction set, very rarely does it point to somewhere else. However the locations it points to in these cases are exactly where the code blocks begin.

Action: 
- Looking at the 3rd values for pattern changes noting when it becomes relevant.

### Layer 5: A Pattern of Execution 

If we look at the first block of code, a pattern emerges:

```
loc 4330:        int[16]         int[19]               4333
loc 4333:              4345            4345            4336
loc 4336:        int[19]               4345            4339
loc 4339:              4346            4346            4342
loc 4342:        int[19]               4346            4345
loc 4345:                 0               0            4348
loc 4348:              4355            4355            4351
loc 4351:        int[19]               4355            4354
loc 4354:        int[11]                  0            4357
```

`int[16]` is (in this case) 1, `int[19]` has a value that starts at `-4541`. This pattern, if you start looking for it, is EVERYWHERE in the program. It can be found both in its tape and in execution. While everything is eventually analyzed breaking down what happens here can be a very handy shortcut for when this pattern pops up.

- The value of `int[16]` (1) is subtracted from `int[19]` (negative of its own location) thus resulting in the first value outside of preprogramed memory.
- The value at 4345 is cleared (X-X = 0).
- The value at `int[19]` is moved to the same location.
- The above 2 steps also happens for 4346.
- Because of the two moved addresses, the location 4542 is cleared.
- The value of `int[11]` is loaded into this memory region.

If you start looking for this pattern you will see it everywhere in the program.

Observations: 
- This program uses `int[19]` locations to write things into the scratch area.
- If you look at all references to `int[16]` nothing seems to alter it.
- You can verify both of these facts by watching the execution live.
- An incredibly similar pattern appears when you look for the inverse. Looking for this pattern you can identify another constant, `int[14]`. An example of this inverse pattern can be found at 4435. This pattern shows that an area is loaded into another location in program memory, `int[9]`.

Actions:
- Naming `int[19]` as `scratch_p`.
- Positively identifying `int[16]` as a constant, renaming this to `one_const`. Do the same thing with `int[14]` as `neg1_cnst`.
- In the future, notice this pattern of execution, and quickly skip over it as loading or storing values into unwritten tape.
### Layer 6: Weird Instructions and Shifting

At this point, there seems to be discrepancies between instruction position and what is actually being executed in the emulator. With the observation in Layer 4, we know that in practice that `int` or `scratch` areas are never actually executed as instructions. What is going on here?

By returning to the first block of instructions in execution we can perhaps see the answer. Starting from 4489...

```
loc 4489:        one_const       scratch_p             4492
loc 4492:              4504            4504            4495
loc 4495:        scratch_p             4504            4498
loc 4498:              4505            4505            4501
loc 4501:        scratch_p             4505            4504
loc 4504:                 0               0            4507
loc 4507:              4514            4514            4510
loc 4510:        scratch_p             4514            4513
loc 4513:              4516               0            3166
loc 4516:              4517      neg1_cnst       scratch_p 
loc 4519:              4520      int[15]         int[15]   
loc 4522:                -1
```

That seems strange. There is an instruction in 4522 that gets a character, but if we check 4523 and 4524, its `-2` and `0`,  so its safer to assume that the program does not work this way. However, if we treat 4516 as a special value and start processing instructions normally, we can see that normal instructions return.

```
loc 4489:        one_const       scratch_p             4492
loc 4492:              4504            4504            4495
loc 4495:        scratch_p             4504            4498
loc 4498:              4505            4505            4501
loc 4501:        scratch_p             4505            4504
loc 4504:                 0               0            4507
loc 4507:              4514            4514            4510
loc 4510:        scratch_p             4514            4513
loc 4513:              4516               0            3166
loc 4516:              4517      
loc 4517:        neg1_cnst       scratch_p             4520      
loc 4520:        int[15]         int[15]                 -1
```


Observations: 
- There is special locations that correlate with some jumps that will offset program execution.
- These correlate with subsequent instructions becoming misaligned.
- This special value is written to the scratch area - just before a jump.
-  After the jump the program points to the next set of instructions.

Action: keep track of these special locations, and offset the instruction parsing to compensate when identified.
### Layer 7: Variables & Constants

At this point, I started noticing that outside of a rare few exceptions, most of the data being processed is either instructions being altered as above, or specific areas in memory we have already identified as `int[x]`. However, a careful observation shows that only certain `int[x]` are being altered, and other `int[x]` are being just read and never being altered. 

So, going through each mention of `int[` via a grep command, we can see the instructions that are altering the values, and those that are simply fixed and never touched. And also for good measure, you should be verifying the findings in the emulator. With this methodology in place, here are some identified variables and constants.

Observations:

| location  | rename   | value |
| --------- | -------- | ----- |
| -1        | special  | N/A   |
| `int[1]`  | neg2_cst | -2    |
| `int[2]`  | zero_cst | 0     |
| `int[3]`  | ten_cst  | 10    |
| `int[4]`  | two_cst  | 2     |
| `int[5]`  | three_c1 | 3     |
| `int[6]`  | four_cst | 4     |
| `int[7]`  | three_c2 | 3     |
| `int[8]`  | blockloc | 1203  |
| `int[14]` | neg1_cst | -1    |
| `int[16]` | one_cst  | 1     |
Now that these have been renamed lets move onto the harder part, the variables. What is left of int seems to be the following:

| location    | behavior                                                                                               | name?        |
| ----------- | ------------------------------------------------------------------------------------------------------ | ------------ |
| 4541        | covered, named `scratch_p`                                                                             | scratchp     |
| `int[9-13]` | tough to say, it does seem to be used for many things including data from scratch, and also processing | ???          |
| `int[15]`   | almost exclusively used for moving variables, cleared after each major use.                            | MOV          |
| `int[17]`   | rarely used, only used to subtract 1, or subtract zero, referenced 4 other times in the program        | ???          |
| `int[18]`   | variable used in conjunction with above variables to store and retrieve values                         | scratch_p_2? |

Actions:
- Renaming the variables and constants when applicable.
- Closely observing the variables to see if the functionality can be further discerned.
### Layer 8: Wait.... No...

Looking closer at `int` values from `9` through `13`, you can make a reasonable guess based on the behavior in the program.

Observation: 
- You can guess that these are registers. The same can be said for `int[17]`. For what they are used for we haven't reached that layer yet. With each usage they are most likely cleared before processing more data. The term most akin to this behavior is a register.

Action:
- Rename each int as `reg_` a through e, and `int[17]` as `stor_reg`.

### Layer 9: ***IT HAS A STACK?!?!?***

When I had all this figured out, that is all I could shout for a solid hour. At this point, I had spent over 30 hours on this challenge alone. So to my surprise, this does indeed have a stack. 

Observation: 
- Looking at each time that `scratch` and `scratch_p` was used, certain things becomes obvious to anyone who is familiar with normal assembly.
- Each time scratch is used it is either for storing/retrieving a specific value, location or a register. And almost every time that is done, either `scratch_p` or `scratch_p_2` is adjusted by 1 or negative 1. 
- This is behavior almost entirely consistent with a stack.

Once you are at this point, the rest of the layers click into place pretty quickly. 

Actions:
- Rename the two variables as `RSP` and `RBP` .
- Reconceptualize the program behavior as something closer to a traditional processor. 

### Layer 10: Loops & Calls

If you take the fact that the Turing Machine has a stack into consideration, then when you look at where jumps are happening, the storage of variables and also positions in the tape start to take on a new meaning.

Observations:
- With the previous loop talked about between 2728 and 2995, examination shows that it will jump only when a certain value in the stack, referenced by RBP, is equal to zero (after abstracting away the registers). Each time, decrementing the value by one.
- Similarly when the Turing machine jumps major sections of tape it will first push a value to the stack, which points to the next instruction after the jump, and if you follow execution all the way back you can see a similar jump back using this value. What I just described is a call. For function calls, speaking from general knowledge outside of this challenge, they usually take the state of the registers, or the state of the stack in some cases. 

Actions:
- First recognize loops, and be able to summarize what the loop does, rather than following raw execution.
- Take stock of what the register values are supposed to represent when execution reaches the call, and use that to enhance greater understanding of the said function call.

### Layer 11: This Sounds Like, Walks Like, and Looks Like C

Now this is where real analysis of the program can begin. After understanding all of these layers, interpreting 100 instructions becomes quick enough and only takes minutes. The program has stacks, the program has registers, and the program does function calls and operations. Call me crazy, but this is starting to sound like C.

Observations: 
- Going through the program tape this intuition can be verified by simply trying to recreate what it would look like in C substituting out registers and stack locations for interpretable variables when possible.

Action: 
- Simply writing down a script like version of what the code is doing will be enough to get to the next layer.

### Layer 12: Recreating C Functions

This is the final layer of abstraction needed to understand this program at last. If you decompile the code correctly you should come away with 3 functions. I will describe them here in general terms:

- `printchar(char c)` - this function is called upon whenever the program decides to print a given character. Seeing this in action it will print a character and then print a newline.
- `checkval(blockval b)` - This function will take the value found by an index plus the offset to Block 2, and... check if it is even or odd. If it is odd, it will return a value to print the character with the same index in the third block as given in the second block. If it is even, then it will not print a character. Because of how the program works, (there is no easy way of telling even-ness), it will subtract 1 from the obtained number and flip an indiciator value from positive to negative for every number subtracted. This is where the "substandard optimization" comes from. 
- `Main_loop()`- this is the main program. This program will loop through the entire block, and send the value to `something()`. If it returns a true value, it will print the associated character in the ascii block. If negative, it will simply jump back to the start of the loop to feed `something()` the next block value.

This program, as you can see, is WILDLY inefficient. For the program to get through all of its letters, it would need to go through a heaping load of numbers. it would need to iterate approximately `1923922857546` times, each iteration taking upwards of 10 plus instructions. That is almost 20 trillion emulated instructions! No wonder it is slow!

An approximate decoding of the program is below. very messy, but so is the operations done within the code
```c
main(){
    mainfunc();
    exit();
}

main_func(){
for(RBP[3] = 0, 
    RBP[2] = blockloc, 
    RBP[1] = 3, ????;

    RBP[3] > Blocklen - 1;

    RBP[3]++){
        if (RBP[3] > blocklen-1){
            return
        }
        checkval(val[RBP[3]+RBP[2]])
        RBP[4] = -stor_reg //printed char

        if (RBP[4] == 1){
            printchr(val[RBP[3]+RBP[1]]);
            printchr('\n');
        }
    }
}
// uses RSP[-1]
printchr(char c){
    print(c);
    stor_reg = -c;
}

checkval(){
    reg_c = RBP[-2]
    if(RBP[-2] == 1){
        reg_b = 1;
        stor_reg = 0;
        jump 3085;
    } else if (RBP[-2] == -2){
        reg_b = 1;
        stor_reg = -1;
        jump 3085;
    }else{
        RBP[-1] = 1
        while(RBP[-2] != 0){
            RBP[-2] = RBP[-2] - 1;
            RBP[-1] = -RBP[-1];
        }
        reg_a = -RBP[-1]
        reg_c =  RBP[-1]
        reg_b =  RBP[-1]
        if(RBP[-1] == 1){
            stor_reg = 0

        } else{
            if (RBP[-1] > 1){
                reg_b = 0
            }
            stor_reg = -1
        }
    } 
}
```

## Decoding the Flag

Now that the program has been fully understood and in a readable format the algorithm becoming clear. All that is left to do is to print out the flag by iterating over the block and printing the associated ascii character when `something()` would have returned true.

And this gives the flag!

https://labs.hackthebox.com/achievement/challenge/158887/257

## Extra Information

I had discovered after finding the solution about how the Challenge was created. The creator, clubby789, had dropped a hint:

>The subleq program was compiled using Higher Subleq - there is a paper on this program which explains some of the design

It turns out that Subleq is exactly what this program was written in. Its named after "SUBtract and Less than or EQual to zero". And without knowing it, I decompiled the program into Higher Subleq, which is a C++ like language. If you want to read more about either, a link to a Wikipedia article is [here](https://esolangs.org/wiki/Higher_Subleq).

Code:
Emulation code:
```python
import binascii
import struct
import os
import curses

# Constants
HEADER_OFFSET = 0x1000
DATA_START = 0x4040 - HEADER_OFFSET
DATA_LENGTH_WORDS = 4541
PADDING_COUNT = 200
STACK_OFFSET_THRESHOLD = DATA_LENGTH_WORDS * 4
CONST_REG_BASE = 4522
BLOCK_START = 1203

class Instruction:
    """
    Represents a single VM instruction with two registers (a, b) and next instruction pointer.
    """
    def __init__(self, reg_a: int, reg_b: int, next_ip: int):
        self.reg_a = reg_a
        self.reg_b = reg_b
        self.next_ip = next_ip

class TuringMachine:
    """
    A simple VM represented by a list of integers as its program and a program counter.
    """
    def __init__(self, program: list[int], pc: int = 0):
        self.program = program
        self.pc = pc

    @classmethod
    def from_file(cls, filename: str) -> 'TuringMachine':
        """
        Load a binary file, extract encoded program data, and initialize the TuringMachine.
        """
        with open(filename, "rb") as f:
            raw_data = bytearray(f.read())

        # Extract instruction words
        start = DATA_START
        length_bytes = DATA_LENGTH_WORDS * 4
        encoded = raw_data[start: start + length_bytes + 4]
        program = []
        for i in range(0, len(encoded), 4):
            value = struct.unpack('<i', encoded[i:i + 4])[0]
            program.append(value)

        # Pad with negative values to avoid crashing
        for x in range(PADDING_COUNT):
            program.append(-x)

        return cls(program)

    def step(self) -> tuple[int, int, int | None]:
        """
        Execute one VM step. Returns a tuple of (prev_b_value, b_index, old_pc).
        """
        a = self.program[self.pc]
        b = self.program[self.pc + 1]
        next_ip = self.program[self.pc + 2]

        prev_b_val = 0
        old_pc = 0

        # Input instruction: reg_a == -1
        if a == -1:
            prev_b_val = self.program[b]
            char = input("Input required: ")
            if char:
                # Mask out upper bytes, store only low 8 bits
                new_val = (ord(char[0]) & 0xFF) | (self.program[b] & 0xFFFFFF00)
                self.program[b] = new_val
            self.pc += 3

        # Output instruction: reg_b == -1
        elif b == -1:
            out_val = self.program[a] & 0xFF
            print("Output:", chr(out_val))
            self.pc += 3

        # Arithmetic/jump instruction
        else:
            prev_b_val = self.program[b]
            self.program[b] -= self.program[a]
            if self.program[b] < 1:
                if next_ip == -1:
                    print("Exiting...")
                    exit(0)
                old_pc = self.pc
                self.pc = next_ip
            else:
                self.pc += 3

        return prev_b_val, b, old_pc

class MemoryDisplay:
    """
    Handles rendering the VM memory to the terminal using curses.
    """
    def __init__(self, tm: TuringMachine, fixed_cols: int):
        self.tm = tm
        self.start_line = 0
        self.fixed_cols = fixed_cols

    def format_value(self, idx: int, value: int, a_idx: int, b_index: int) -> str:
        """
        Convert a raw integer value into a display string, handling constants, stacks, registers,
        hex region, and ASCII for memory beyond that.
        """
        # Detect stack-related values
        if STACK_OFFSET_THRESHOLD < abs(value) < STACK_OFFSET_THRESHOLD + PADDING_COUNT:
            offset = abs(value) - (STACK_OFFSET_THRESHOLD + 1)
            return f"{'stack+' if value > 0 else 'stack-'}{offset}"

        # Constants and registers in the CONST_REG_BASE range
        if CONST_REG_BASE < value < CONST_REG_BASE + 25:
            reg_map = {
                4523: "neg2_cst", 4524: "zero_cst", 4525: "ten_cst", 4526: "two_cst",
                4527: "three_cst", 4528: "four_cst", 4529: "3_cst", 4530: "blockloc",
                4536: "neg1_cst", 4538: "one_cst",
                4531: "reg_a", 4532: "reg_b", 4533: "reg_c", 4534: "reg_d", 4535: "reg_e",
                4537: "MOV", 4539: "stor?", 4540: "RBP", 4541: "RSP"
            }
            return reg_map.get(value, f"int[{value - CONST_REG_BASE:2}]")

        # Block addresses
        if BLOCK_START <= value < BLOCK_START * 2-1:
            return f"blk[{value - BLOCK_START:2}]"

        # Display hex for memory addresses in the first block
        if BLOCK_START <= idx < BLOCK_START * 2-1:
            return hex(value)

        # Beyond hex region: display low byte as ASCII if printable
        if idx <= BLOCK_START:
            if 32 <= value < 127:
                return chr(value)

        # Default: display decimal
        return str(value)

    def draw(self, stdscr, prev_b_val: int | None, b_index: int, old_pc: int | None, instr_num: int):
        stdscr.clear()
        max_y, max_x = stdscr.getmaxyx()
        prompt = "Press Enter for next step..."

        # Header lines
        header = f"#{instr_num}: PC={self.tm.pc}"
        if old_pc is not None:
            header += f", Jumped from {old_pc}"
        stdscr.addstr(0, 0, header)
        if prev_b_val is not None:
            stdscr.addstr(1, 0, f"Prev B[{b_index}] = {prev_b_val}")

        # Current instruction decode
        idx = self.tm.pc
        a_idx = self.tm.program[idx]
        b_idx = self.tm.program[idx + 1]
        c_val = self.tm.program[idx + 2]
        a_val = self.tm.program[a_idx]
        b_val = self.tm.program[b_idx]
        instr_line = f" Instr: A=prog[{a_idx}]({a_val}) B=prog[{b_idx}]({b_val}) C={c_val}"
        stdscr.addstr(2, 0, instr_line)

        # Render register snapshot at fixed offset
        reg_base = CONST_REG_BASE + 9
        regs = [self.tm.program[reg_base + i] for i in range(5)]
        rsp = self.tm.program[CONST_REG_BASE + 19]
        rbp = self.tm.program[CONST_REG_BASE + 18]
        reg_line = (
            f"RSP={rsp}  A={regs[0]} B={regs[1]} C={regs[2]} D={regs[3]} E={regs[4]} "
            f"MOV={self.tm.program[CONST_REG_BASE + 15]} "
            f"stor={self.tm.program[CONST_REG_BASE + 17]} RBP={rbp}"
        )
        stdscr.addstr(3, 0, reg_line)

        # Draw memory grid with fixed column count
        available_lines = max_y - 5
        start = self.start_line * self.fixed_cols
        end = min(start + available_lines * self.fixed_cols, len(self.tm.program))
        row, col = 4, 0
        for i in range(start, end):
            val_str = self.format_value(i, self.tm.program[i], a_idx, b_index)
            # Highlight special indices
            if i == idx:
                stdscr.addstr(row, col, f"[{val_str:^8}]", curses.color_pair(2))
            elif i == idx + 1:
                stdscr.addstr(row, col, f"({val_str:^8})", curses.color_pair(3))
            elif i == idx + 2:
                stdscr.addstr(row, col, f"<{val_str:^8}>", curses.color_pair(4))
            elif i == a_idx:
                stdscr.addstr(row, col, f"*{val_str:^8}*", curses.color_pair(2))
            elif i == b_idx:
                stdscr.addstr(row, col, f"*{val_str:^8}*", curses.color_pair(3))
            elif i == c_val:
                stdscr.addstr(row, col, f"#{val_str:^8}#", curses.color_pair(4))
            elif b_index is not None and i == b_index:
                stdscr.addstr(row, col, f" {val_str:^8} ", curses.color_pair(1))
            else:
                stdscr.addstr(row, col, f" {val_str:^8} ")
            col += 12
            if col + 12 > max_x:
                col = 0
                row += 1
                if row >= available_lines + 4:
                    break

        # Footer prompt
        stdscr.addstr(max_y - 1, 0, prompt[:max_x])
        stdscr.refresh()
        return True


def main(stdscr):
    # Initialize colors
    curses.start_color()
    curses.init_pair(1, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)

    # Determine fixed column count based on initial window size
    initial_max_x = stdscr.getmaxyx()[1]
    fixed_cols = max(1, initial_max_x // 12)

    # Load and run VM
    tm = TuringMachine.from_file("substandard")
    display = MemoryDisplay(tm, fixed_cols)
    instr_count = 0
    prev_b_val = 0
    b_idx = 0
    old_pc = 0

    while True:
        display.draw(stdscr, prev_b_val, b_idx, old_pc, instr_count)
        key = stdscr.getch()
        if key in (curses.KEY_ENTER, 10):
            prev_b_val, b_idx, old_pc = tm.step()
            instr_count += 1
        elif key == curses.KEY_UP:
            display.start_line = max(0, display.start_line - 1)
        elif key == curses.KEY_DOWN:
            max_lines = (len(tm.program) - 1) // display.fixed_cols
            display.start_line = min(max_lines, display.start_line + 1)
        else:
            # Exit on any other key
            break

if __name__ == "__main__":
    curses.wrapper(main)
```

block breakdown code:
```python
import struct
import matplotlib.pyplot as plt
import numpy as np

# Constants for file parsing
HEADER_OFFSET = 0x1000
DATA_START = 0x4040 - HEADER_OFFSET
DATA_LENGTH_WORDS = 4541
PADDING_COUNT = 20  # padding count for overkill

# Constant and register value mappings
CONST_BASE = 4522
CONST_MAP = {
    CONST_BASE + 1: "neg2_cst", CONST_BASE + 2: "zero_cst", CONST_BASE + 3: "ten_cst", CONST_BASE + 4: "two_cst",
    CONST_BASE + 5: "three_c1", CONST_BASE + 6: "four_cst", CONST_BASE + 7: "three_c2", CONST_BASE + 8: "blockloc",
    CONST_BASE + 14: "neg1_cst", CONST_BASE + 16: "one_cst",
    CONST_BASE + 9: "reg_a", CONST_BASE + 10: "reg_b", CONST_BASE + 11: "reg_c", CONST_BASE + 12: "reg_d", CONST_BASE + 13: "reg_e",
    CONST_BASE + 15: "MOV", CONST_BASE + 17: "stor_reg", CONST_BASE + 18: "RBP", CONST_BASE + 19: "RSP"
}

# Instruction comments mapped by index
COMMENTS = {
    2433: "# sets RSP to RBP, makes space for 2",
    2439: "# push reg_a",
    2466: "# push reg_b",
    2494: "# push reg_c",
    2520: "# reg_c = reg_b = RBP[-2] = val[RBP[3] + RBP[2]]",
    2562: ("# if RBP[-2]/reg_b == 1: stor_reg = 0; jump 3085 "
            "else: jump 2599"),
    2598: "# reg_c = reg_b = RBP[-2]",
    2649: ("# if RBP[-2] == 2: reg_b = 1; jump 3085 "
            "else: continue"),
    2676: "# RBP[-1] = 1",
    2727: "# reg_c = reg_b = RBP[-2]",
    2778: ("# if RBP[-2] == 0: jump 2998 "
            "else: continue"),
    2784: "# reg_c = reg_b = RBP[-2]",
    2835: "# RBP[-2] = RBP[-2] - 1",
    2889: "# reg_c = RBP[-1]",
    2928: "# reg_b = -RBP[-1]",
    2946: "# RBP[-1] = -RBP[-1]",
    2997: "# reg_a = -RBP[-1]; reg_c = RBP[-1]; reg_b = RBP[-1]",
    3048: ("# if (RBP[-1] == 1) { stor_reg = 0 } else { if (RBP[-1] > 1) { reg_b = 0 }; stor_reg = 1 }"),
    3084: "# pop reg_c; pop reg_b; pop reg_a",
    3165: "# main_func: pushes RBP to stack",
    3192: "# init RBP stack, moves RSP up to give 5 values for RBP",
    3204: "# sets reg_a to RSP stack",
    3228: "# sets reg_b to RSP stack",
    3255: "# sets reg_c to RSP stack",
    3282: "# sets reg_d to RSP stack",
    3309: "# sets reg_e to RSP stack",
    3336: "# moves 3 into RBPstack[1]",
    3387: "# moves blockloc onto RBPstack[2]",
    3438: "# moves 0 onto RBPstack[3]",
    3489: "# jump: RBP[3] > Blocklen - 1",
    3546: "# if false, get RBPStack[2] into reg_d",
    3585: "# get RBPStack[3] into reg_e",
    3624: "# RBPStack[3] + RBPStack[2] into reg_c",
    3639: "# val[RBPStack[3] + RBPStack[2]] into reg_e",
    3663: ("# push result (counter + blockloc) to stack; "
            "set reg_a, reg_b, reg_c, reg_d, reg_e, RSP, stor_reg accordingly"),
    3724: "# RBP[4] = reg_e",
    3730: "# post call instr",
    3733: "# sets RBP[4] to -stor_reg",
    3784: "# gets RBP[4]",
    3853: "# reg_c = RBP[1]",
    3898: "# reg_d = RBP[3]",
    3937: "# reg_b = RBP[1] + RBP[3]",
    3952: "# reg_d = val[RBP[3] + RBP[1]]",
    3970: "# val[RBP[3] + RBP[1]] pushed to stack",
    4003: "# call printchr; RSP[-1] = val[RBP[3] + RBP[1]]",
    3835: ("# this took too long; if RBP[4] == 1 continue; "
            "else: reg_b = 0; jmp 4099"),
    4488: ("# Init block; call 3316; set reg_a, reg_b, reg_c, reg_d, reg_e, stor_reg, RBP appropriately"),
    4034: "# Calls printchr(LF/newline)",
    4037: "# newline (LF=10) pushed to stack",
    4067: "# return location pushed to stack",
    4091: "# call printchr(LF/newline)",
    4098: "# increments RBP[3], starts loop again",
    4131: "# moves RSP[0] (returned val) into reg_e",
    4143: "# moves RSP[-1] into reg_d",
    4158: "# moves RSP[-2] into reg_c",
    4173: "# moves RSP[-3] into reg_b",
    4188: "# moves RSP[-4] into reg_a",
    4128: "# jumps to 3490",
    4212: "# moves RSP[0] into RBP",
    4224: "# returns to caller",
    4242: ("# printchar subroutine: takes RSP[-1], stor_reg -= char; "
            "push RBP, set RSP, push reg_a, reg_b, reg_c, print, stor_reg, pop regs, pop RSP, return"),
    4269: "# set RSP to RBP",
    4275: "# push reg_a",
    4302: "# push reg_b",
    4329: "# push reg_c",
    4356: "# PRINT RSP[-1]",
    4398: "# stor_reg = -RSP[-1]",
    4404: "# pop reg_c",
    4420: "# pop reg_b",
    4434: "# pop reg_a",
    4449: "# pop RSP, reset RSP",
    4470: "# return to caller"
}


def load_program(filename: str) -> list[int]:
    """
    Load binary data from file, decode 32-bit little-endian signed integers,
    and append padding values.
    """
    with open(filename, "rb") as f:
        data = bytearray(f.read())

    start = DATA_START
    byte_length = DATA_LENGTH_WORDS * 4
    encoded = data[start : start + byte_length + 4]

    program: list[int] = []
    for i in range(0, len(encoded), 4):
        value = struct.unpack('<i', encoded[i : i + 4])[0]
        program.append(value)

    # Pad with large negative values to avoid crashes
    for i in range(PADDING_COUNT):
        program.append(-((1 << 32) - 1) * (i + 1))

    return program


def map_value_to_label(x: int) -> str:
    """
    Convert a raw integer x to a human-readable label.
    """
    # Special markers
    if x == -1:
        return "special"
    if x == 0:
        return "0"
    if x == 2403:
        return "blocklen"
    if x == 4243:
        return "printchr"

    # Memory or constant region
    if x > CONST_BASE:
        if x in CONST_MAP:
            return CONST_MAP[x]
        if x > CONST_BASE and x < CONST_BASE + 20:
            return f"int[{x - CONST_BASE}]"
        if x > DATA_LENGTH_WORDS:
            return f"mem_{abs(x) - DATA_LENGTH_WORDS}"

    # ASCII region
    if 2 < x < 1203:
        return f"chr[{x}]"

    # Block labels
    if 1203 <= x < 2403:
        return f"blk[{x}]"

    # Default: decimal
    return str(x)


def print_initial_blocks(program: list[int]) -> None:
    """
    Print the initial instruction block (first 3 values), ASCII block (3 to 1202),
    and hex block (1203 to 2402).
    """
    print("Initial Instruction Block:")
    for idx in range(3):
        print(program[idx], end="  ")
    print("\n")

    print("ASCII Block (indices 3..1202):")
    for x in program[3:1203]:
        print(chr(x), end="")
    print("\n\n")

    print("Hex Block (indices 1203..2402):")
    for x in program[1203:2403]:
        print(hex(x), end=" ")
    print("\n")


def print_program_block(program: list[int]) -> None:
    """
    Print labeled instructions for the main program block (2404..4522) in a single-line format.
    """
    print("Start of Program Block:")
    for idx in range(2404, 4523, 3):
        # Insert comment if present
        if idx in COMMENTS:
            print(f"{COMMENTS[idx]}")
        if idx+1 in COMMENTS:
            print(f"{COMMENTS[idx+1]}")
        if idx+2 in COMMENTS:
            print(f"{COMMENTS[idx+2]}")
        a = program[idx]
        b = program[idx + 1]
        nxt = program[idx + 2]

        a_label = map_value_to_label(a)
        b_label = map_value_to_label(b)
        nxt_label = map_value_to_label(nxt)

        print(f"loc {idx}: {a_label:<12} {b_label:<8} {nxt_label}")
    print("\nEnd of Program Block.\n")


def print_stack_and_constants(program: list[int]) -> None:
    """
    Print the stack or constant blocks (indices 3..1202 and 1203..2402) in formatted arrays.
    """
    stack_vals = program[3:1203]
    const_vals = program[1203:2403]

    print("Block of ascii Values (formatted):")
    for i in range(0, len(stack_vals), 30):
        print(stack_vals[i : i + 30])
    print("\n")

    print("Block of Constant Values (formatted):")
    for i in range(0, len(const_vals), 20):
        print(const_vals[i : i + 20])
    print("\n")


def print_constants(program: list[int]) -> None:
    """
    Print constant region values (indices 4523..4541).
    """
    print("Constants Region:")
    for idx in range(4523, 4542):
        print(f"{program[idx]:8}", end=" ")
    print("\n")


def plot_value_distribution(values: list[int]) -> None:
    """
    Plot a histogram of value distribution.
    """
    values_array = np.array(values)
    plt.figure(figsize=(10, 6))
    plt.hist(values_array, bins=200, edgecolor='black', alpha=0.7)
    plt.title('Value Distribution in Turing Machine Tape')
    plt.xlabel('Value')
    plt.ylabel('Frequency')
    plt.show()


def plot_scatter_distribution(values: list[int]) -> None:
    """
    Plot a scatter of values versus their indices.
    """
    values_array = np.array(values)
    indices = np.arange(len(values_array))
    plt.figure(figsize=(12, 6))
    plt.scatter(indices, values_array, alpha=0.6, edgecolors='w', s=50)
    plt.title('Scatter Plot of Value Distribution in Turing Machine Tape')
    plt.xlabel('Position in Array')
    plt.ylabel('Value')
    plt.show()


def main():
    program = load_program("substandard")

    # Display initial blocks
    print_initial_blocks(program)

    # Display program instructions with labels
    print_program_block(program)

    # Display stack and constant arrays
    print_stack_and_constants(program)

    # Display constants region
    print_constants(program)

    # Optional: plot distributions (commented out by default)
    # cipherblock = [x for x in program[1203:2403]]
    # plot_scatter_distribution(cipherblock)

if __name__ == "__main__":
    main()
```

Flag deciphering code:
```python
chars = [122, 41, 119, 56, 81, 40, 53, 97, 108, 75, 100, 63, 43, 75, 111, 116, 66, 72, 114, 60, 92, 61, 66, 113, 75, 51, 69, 101, 125, 78,
117, 111, 40, 102, 122, 126, 108, 35, 41, 89, 111, 90, 96, 92, 46, 73, 33, 77, 90, 84, 121, 40, 80, 109, 55, 44, 65, 50, 63, 67,
61, 52, 113, 42, 92, 58, 77, 68, 52, 100, 35, 123, 118, 125, 84, 110, 65, 67, 102, 79, 98, 82, 85, 114, 112, 38, 66, 64, 82, 36,
76, 66, 56, 41, 82, 62, 32, 111, 58, 84, 103, 36, 64, 82, 53, 43, 83, 73, 121, 67, 87, 69, 106, 75, 39, 111, 124, 75, 113, 32,
102, 85, 104, 123, 49, 63, 54, 121, 40, 90, 109, 34, 91, 51, 121, 126, 98, 47, 94, 53, 36, 41, 53, 99, 99, 124, 77, 101, 49, 101,
88, 104, 53, 42, 40, 38, 69, 61, 82, 112, 117, 125, 39, 61, 105, 75, 84, 94, 85, 72, 37, 98, 55, 111, 121, 36, 70, 34, 79, 42,
98, 126, 67, 78, 105, 55, 44, 108, 57, 114, 98, 60, 111, 40, 126, 36, 117, 104, 79, 40, 54, 93, 72, 95, 49, 52, 109, 72, 51, 67,
74, 93, 43, 44, 69, 87, 51, 52, 85, 79, 73, 54, 82, 60, 83, 94, 35, 55, 67, 59, 81, 37, 94, 59, 114, 108, 103, 113, 76, 55,
45, 36, 96, 105, 41, 75, 122, 118, 82, 32, 51, 117, 72, 82, 44, 73, 61, 88, 116, 81, 51, 47, 67, 110, 92, 66, 104, 101, 117, 46,
51, 67, 62, 72, 113, 111, 114, 99, 114, 116, 45, 78, 101, 49, 117, 35, 83, 74, 95, 50, 53, 62, 41, 32, 119, 90, 124, 63, 36, 108,
69, 46, 102, 62, 74, 90, 34, 39, 99, 37, 88, 38, 110, 75, 92, 85, 42, 100, 121, 107, 49, 84, 105, 91, 117, 32, 35, 78, 75, 40,
73, 73, 38, 109, 95, 116, 86, 75, 51, 52, 60, 92, 120, 123, 83, 102, 109, 94, 85, 125, 60, 123, 93, 113, 73, 67, 62, 38, 118, 60,
49, 120, 93, 94, 46, 111, 70, 63, 80, 121, 64, 95, 72, 46, 57, 35, 65, 60, 73, 46, 62, 68, 81, 38, 48, 93, 67, 61, 104, 94,
89, 106, 63, 58, 61, 110, 82, 73, 84, 43, 38, 95, 103, 57, 33, 92, 52, 90, 103, 65, 117, 57, 45, 53, 52, 65, 90, 67, 37, 125,
118, 115, 67, 104, 51, 89, 108, 84, 59, 112, 120, 33, 112, 87, 109, 59, 86, 68, 61, 45, 68, 48, 61, 36, 92, 121, 34, 95, 116, 106,
54, 69, 89, 109, 98, 89, 70, 82, 101, 107, 110, 88, 65, 52, 53, 71, 61, 70, 51, 109, 114, 104, 90, 97, 55, 45, 105, 50, 88, 42,
110, 66, 122, 124, 61, 40, 47, 116, 52, 45, 65, 73, 98, 51, 76, 114, 124, 38, 35, 33, 48, 85, 64, 53, 95, 33, 76, 123, 117, 99,
105, 37, 56, 102, 121, 51, 79, 105, 116, 67, 80, 121, 107, 44, 105, 44, 53, 75, 42, 110, 94, 106, 66, 89, 33, 55, 52, 105, 74, 111,
110, 121, 122, 77, 92, 84, 72, 107, 96, 108, 40, 38, 68, 73, 116, 66, 42, 113, 85, 103, 61, 33, 97, 44, 75, 105, 63, 92, 77, 95,
105, 63, 57, 43, 124, 122, 108, 80, 61, 94, 81, 40, 88, 88, 55, 82, 45, 35, 100, 125, 109, 69, 108, 59, 51, 125, 32, 55, 104, 89,
78, 124, 107, 36, 64, 36, 71, 48, 109, 92, 53, 36, 126, 53, 84, 91, 92, 117, 47, 79, 41, 48, 95, 69, 101, 45, 70, 61, 108, 32,
59, 33, 96, 93, 118, 58, 106, 89, 103, 35, 76, 109, 113, 63, 98, 52, 80, 109, 43, 88, 36, 100, 108, 108, 93, 85, 56, 125, 83, 59,
114, 78, 103, 121, 43, 108, 122, 49, 82, 54, 123, 117, 97, 93, 114, 85, 88, 85, 56, 105, 89, 105, 57, 43, 93, 67, 40, 83, 66, 116,
74, 107, 101, 69, 73, 123, 62, 56, 95, 83, 71, 34, 118, 53, 37, 73, 55, 64, 83, 90, 60, 85, 110, 52, 45, 38, 62, 119, 47, 76,
125, 79, 90, 79, 85, 114, 36, 107, 79, 45, 74, 85, 57, 37, 47, 115, 97, 66, 58, 104, 57, 99, 91, 114, 121, 36, 43, 104, 88, 104,
39, 86, 69, 81, 40, 109, 37, 124, 64, 38, 109, 51, 109, 67, 57, 65, 53, 87, 59, 122, 110, 114, 32, 103, 103, 47, 41, 41, 39, 121,
44, 57, 39, 90, 58, 98, 39, 43, 55, 88, 33, 45, 68, 52, 78, 59, 98, 74, 59, 79, 116, 79, 84, 56, 94, 125, 108, 114, 88, 90,
72, 80, 74, 89, 51, 43, 107, 33, 89, 48, 38, 126, 76, 119, 122, 47, 78, 60, 56, 69, 51, 83, 120, 64, 74, 56, 124, 125, 75, 50,
123, 123, 77, 115, 42, 105, 38, 58, 52, 93, 98, 92, 124, 56, 109, 75, 88, 96, 37, 97, 63, 41, 50, 80, 83, 126, 96, 104, 97, 116,
71, 53, 53, 36, 118, 60, 107, 82, 39, 114, 61, 109, 115, 110, 57, 51, 100, 69, 125, 103, 122, 55, 83, 57, 66, 106, 77, 116, 110, 100,
117, 36, 72, 57, 100, 35, 71, 101, 50, 86, 102, 45, 117, 83, 100, 35, 37, 57, 73, 63, 64, 69, 59, 115, 51, 114, 45, 64, 64, 63,
53, 90, 126, 49, 75, 111, 84, 78, 43, 57, 43, 40, 85, 123, 50, 100, 38, 91, 106, 83, 77, 58, 70, 76, 60, 58, 68, 98, 120, 80,
62, 93, 66, 94, 116, 79, 39, 93, 38, 61, 124, 49, 71, 42, 84, 51, 34, 41, 60, 81, 107, 37, 126, 109, 87, 125, 70, 46, 91, 51,
51, 36, 113, 43, 107, 84, 63, 62, 85, 81, 53, 72, 95, 102, 70, 77, 85, 67, 110, 76, 122, 121, 43, 118, 51, 84, 43, 89, 44, 35,
49, 46, 33, 87, 83, 74, 78, 73, 66, 48, 112, 107, 118, 113, 126, 53, 66, 99, 79, 40, 68, 119, 101, 88, 44, 38, 35, 121, 37, 88,
76, 59, 122, 39, 58, 96, 41, 103, 116, 67, 104, 63, 36, 99, 50, 115, 52, 37, 92, 88, 57, 61, 112, 97, 36, 123, 38, 110, 44, 42,
79, 85, 66, 116, 63, 95, 87, 105, 96, 52, 118, 59, 40, 36, 32, 66, 78, 41, 49, 40, 108, 39, 86, 52, 44, 87, 96, 80, 111, 88,
44, 114, 98, 61, 60, 52, 79, 85, 52, 107, 119, 85, 53, 64, 43, 118, 120, 34, 45, 112, 66, 119, 32, 46, 45, 59, 66, 63, 84, 92,
126, 101, 36, 116, 102, 126, 34, 83, 64, 46, 82, 59, 47, 78, 60, 79, 45, 35, 73, 113, 77, 41, 112, 107, 115, 60, 37, 35, 87, 77,
47, 121, 69, 64, 62, 35, 50, 108, 41, 68, 50, 114, 95, 80, 91, 96, 89, 119, 33, 32, 83, 81, 79, 56, 74, 53, 58, 67, 43,]

vals = [2023578122, 1259695380, 1761160110, 1766587580, 1446075810, 2056479588, 1122882462, 1543075980, 1315763292, 2057072264, 1479771288, 1526031180, 1637938488, 1176993864, 1944974124, 1955615100, 1916089430, 2070783079, 1544475030, 1326318398,
1741091588, 1779635904, 1076656298, 1350203178, 1303177194, 1367753292, 1290365864, 1964029580, 1937514302, 1210313652, 1722955824, 1328652440, 1796042772, 1801595582, 1777580172, 1379508218, 2005027238, 1208471318, 1647599102, 1879064168,
2041757192, 1619210270, 1197140454, 1362573300, 1647722408, 2013546384, 1156843718, 1473987410, 1384439318, 1278624731, 1214982852, 1833100932, 1459191102, 2091085122, 1910246870, 1728879908, 2098632008, 1967938934, 1203910134, 1084608720,
1715484224, 2083536732, 1279840478, 1827183864, 1778263704, 1109249250, 1140329922, 1341745800, 1859659212, 1326442532, 2006828754, 1858588490, 1393639518, 1695021512, 1267472022, 1885256364, 1484753244, 1201931874, 1910445932, 2133942260,
1141286682, 1201692894, 1380588708, 1462215858, 1131305322, 1153453664, 2022183271, 1884514692, 1405364190, 1173398138, 1487248818, 1257890354, 1117363020, 1699502072, 1800902952, 1084503230, 1826126892, 1512393888, 1507809888, 1237611708,
1668458484, 1094545148, 2075518310, 1165480332, 1390402218, 1719786024, 1350161900, 1740017568, 1250884890, 1076929488, 1584664868, 1205527824, 1409959220, 1503231050, 1493885808, 1592288334, 1814938638, 1982565282, 1667121078, 1128413750,
1314527762, 1242241844, 1148262614, 1861537987, 1748282052, 1426576934, 2076078702, 1693328712, 2028431372, 1433890190, 1769841324, 1656128108, 2130511298, 1973415078, 1086570228, 1413713210, 1130538012, 1735313844, 2123360664, 1464648623,
2097325472, 1351703342, 1231703702, 2018997342, 1284996522, 2030596274, 1458970134, 1701791402, 2095979342, 1235771682, 1342315698, 1125343998, 1172554812, 1543865124, 2125637490, 2119822512, 1463885538, 1811639328, 2069105918, 1584610884,
2076768163, 1690048532, 1262222262, 2046244470, 1414569648, 1110162324, 1954210530, 1877375000, 1222271804, 1779704192, 2145054758, 1565816690, 1393042230, 1857217424, 1646247830, 1690532168, 1379349800, 1143744410, 1742538312, 1885660748,
1267574219, 1526368800, 1377585480, 1544507634, 1483233420, 1209993510, 2117230148, 1332585480, 2012571308, 2069351258, 1620271028, 1089214542, 1703718018, 1956390168, 1381675490, 2052256182, 1362815600, 2115633104, 1982150124, 1952872037,
1448138960, 1075354128, 1859213388, 1576101134, 1979742594, 1379075228, 1789087688, 2035939274, 1589227460, 2017401368, 1252155902, 1579602002, 1441028484, 1223457942, 1110663294, 1274333384, 1909796588, 2100034950, 1488846450, 1537144310,
2106701684, 1305791274, 1351200518, 1989958050, 1109417958, 1989481760, 1407549492, 2122598100, 1589911124, 1615345688, 2146872132, 1645718210, 1261425554, 1751496084, 1688707478, 1418893471, 1319698650, 1945076954, 1740790350, 2070569804,
1879510380, 1866635628, 1428583790, 1973012264, 1550435490, 1577146508, 2054825868, 1260515624, 1436512508, 1683778208, 1400177257, 1200012002, 2014879344, 2077837982, 2046209358, 1460935914, 1983568340, 1174145738, 1606726842, 1095129518,
2042618840, 1954923098, 1466276408, 2091424242, 1192422812, 1437445382, 1377776064, 1411973418, 1078406082, 1348878464, 1931486904, 1788962294, 1897810694, 1160072562, 1424609933, 1830736658, 1490208722, 1106003078, 1189297818, 1789488318,
1934241242, 1297540662, 1501314434, 1279329134, 2138399358, 1177080692, 1822454478, 1303100178, 1111318994, 1642764482, 1837983998, 1932109562, 1403869637, 1248624474, 1353237378, 1715073528, 1241937734, 1682454470, 1582995092, 1279166843,
1748924480, 1508359814, 1195654848, 1943995562, 1699835498, 2043631088, 1916602742, 1549031294, 1377527934, 1092999450, 1558901052, 1084165548, 1469765742, 1502883662, 1948675368, 1828250574, 1865022254, 1102599438, 1911783564, 1097083568,
1661371639, 2129953458, 1523513324, 1455238668, 1973548388, 1427143692, 1320452798, 1745613968, 1992230000, 1760568290, 1530518918, 1847136228, 1327861860, 1466800422, 1899587178, 1365502200, 1274941002, 1455180108, 1593472472, 1739665424,
1656345152, 1698621920, 1352292542, 1707631208, 1383444654, 1667176800, 1155804569, 1772681528, 1997837720, 1661020430, 1781395670, 1372582764, 1621711622, 1142199974, 2036558012, 1981429092, 1379055200, 2015643990, 1710626340, 1295077920,
1684784483, 1106558864, 1612714604, 1789364124, 2035632420, 1130142752, 1583264142, 1860934194, 2048817228, 1908550584, 1909933508, 1127926058, 2107283744, 1962048758, 1579086750, 1923747318, 1600247864, 2145792558, 1724091528, 2042942108,
1703963030, 1481401194, 2144310002, 1528145498, 2132840058, 1706765010, 1735163292, 1986468662, 1160911092, 1296493454, 1527958508, 1608567750, 1490507402, 1104282368, 1656040770, 1375898297, 1139956202, 1336837098, 1151081132, 1568072352,
1695100098, 1642481948, 1494687518, 1251052784, 2098176902, 1559375054, 1143934944, 2101054452, 1431825768, 1516938024, 1965151338, 1369033824, 1990677104, 1654087148, 1886971283, 1226801232, 1883505750, 1243240764, 1389346734, 1717263470,
2070319370, 1107956082, 1366146044, 1445950014, 1759959998, 1214515958, 2031471269, 1606929228, 1641464172, 1465500854, 2054394194, 1195715322, 2092818038, 2031898692, 1936539288, 1849537932, 1555695684, 1505058642, 1191112610, 1934322654,
1751557950, 2108192630, 1536802230, 1932337550, 1080244872, 1788346752, 1645944342, 2110906043, 1444943778, 1688937024, 1786038848, 2029160814, 1745260212, 1105817408, 1571142894, 1733661390, 2053452278, 2042082354, 1927629024, 1867031894,
1472641088, 1381629582, 1757101428, 1211909082, 1884022758, 1456950138, 1762401738, 2046906108, 1412187534, 1955693527, 1851575444, 1804770860, 1417312484, 2049856658, 1942851902, 1771019714, 1259723300, 1097389664, 1945515312, 1996430352,
1372853564, 1727997450, 2080989134, 1796313108, 1738532924, 1845346404, 1674400574, 1797507884, 1256404652, 1944159788, 1665332100, 1396847762, 1199356430, 1460069329, 1925390340, 1362648098, 1701329910, 2086640694, 1358840570, 1689468930,
1852625162, 1180561364, 2086944612, 1203357521, 2104722732, 1505424564, 1804414764, 2145708554, 2114671104, 1700184644, 1610040942, 1303393980, 1822772514, 1816044170, 1917219878, 1377472752, 1583330928, 1138453430, 1115366480, 1625274128,
1527281954, 1383780942, 1742738972, 1747836408, 1718300804, 1992164724, 1894688281, 1855740980, 1541052170, 1806507612, 1151209448, 1114406370, 1552530558, 1658839034, 1800062478, 1461935874, 1220256013, 2104526580, 1752555590, 1494012758,
1696907912, 1172292060, 1104075210, 2061320448, 2147027834, 1115031278, 1482168362, 1168428804, 1182816962, 1419031844, 1082072688, 1260364542, 2145874814, 1300069448, 1419409998, 1983466232, 1910578290, 1140441360, 1427835090, 1872905081,
1628778024, 1654661040, 2047342502, 1122723258, 1722938874, 2069860614, 1599510014, 1873114392, 2015218398, 2081432700, 1917292562, 1925375160, 1184785700, 1074384918, 1715328072, 1701307278, 1268434622, 1526515122, 1410642972, 1108717244,
1173205754, 1480933998, 1158509348, 1747865262, 2142465738, 1743800394, 1144396334, 1585745334, 1261176590, 1517022054, 1408254570, 1277860262, 1682755688, 2135824352, 1912573903, 2124803454, 2058940614, 1905480792, 1664045268, 1638593928,
1806352694, 1518106022, 1173552278, 1179632394, 1461261804, 1723227578, 1398233450, 2139070758, 1493709740, 1807022564, 1455055214, 2076295238, 1368185852, 1249636393, 1378272384, 1337829114, 1121637372, 1355423054, 1278946968, 2117511534,
1659474248, 1435894602, 1299018270, 1221657038, 1150020482, 1110499032, 1979146832, 2099166008, 1693974740, 1087986854, 1156620320, 1923779197, 1391852378, 1255800972, 1842270152, 1941568428, 1161450702, 1717852028, 2042216640, 1959861878,
2037192702, 1192754160, 1641705048, 1235767782, 1474931960, 1166489522, 2062015640, 1104408290, 1665013952, 1949261310, 1314206382, 1207573542, 1581622280, 1891073784, 2007786044, 1488322542, 1882304112, 1610960623, 1599646358, 2052124344,
1453080620, 1935723068, 1693015128, 1801661418, 1194321450, 2013270404, 1350569940, 2038362854, 1107583680, 1267165554, 2028399002, 1257909968, 1235802392, 1164778962, 1284519782, 1577705190, 1589507658, 1833733368, 1713209490, 1474307124,
1770208568, 1714486902, 1367765138, 1422317154, 1308739142, 1260996008, 1624508814, 1362027102, 1122277680, 1223709200, 1479731088, 1819321808, 2078293292, 1789146278, 1239333770, 1708451318, 1087395410, 1280947860, 1731491762, 1815941874,
1329784398, 1495995144, 1774872150, 2087251238, 1409615528, 1360678244, 1434157784, 1176998172, 1454518194, 1129204502, 1699298748, 1609676618, 1944920210, 1934144394, 1880446004, 1295719490, 1169099880, 1546287732, 1515758450, 1085357438,
1965786078, 1619992110, 1865521550, 1284256218, 1712044560, 1320737220, 1263871380, 1233477630, 1969355618, 1460680548, 1852903478, 1150611462, 2052711528, 1445211332, 1710642072, 1897018100, 1698613730, 1805110262, 2112662712, 2032264082,
1079583458, 1561891572, 1355399108, 1470543584, 1710333908, 1622081940, 1083259928, 1767100970, 1282213400, 1457939514, 1711559418, 1742977830, 1946574944, 1278182618, 1271906850, 1508601450, 1760816612, 1375735662, 1734764108, 1609664234,
1966043610, 1135097372, 2137446980, 1786537148, 1254244628, 1789658132, 1584757244, 2139297158, 1598010188, 2022624128, 1547907458, 1532482448, 1097152868, 1212248114, 1412719454, 1295528888, 1625129532, 1976447312, 1341729548, 2027376182,
1281265598, 1194929064, 2012340918, 1273019442, 1307134274, 2052577700, 1248261170, 1830458418, 1607967000, 1373896110, 1271657060, 1267063662, 1903735314, 1795144032, 1493307848, 1783205130, 1766234312, 1622000382, 1753124520, 1577916540,
1486415042, 1352725064, 1480265922, 1330959278, 1893738378, 1793972432, 1981962020, 1100445540, 1312379508, 2093421764, 1817750252, 1161425100, 1479143774, 1245754754, 2015160950, 1546985240, 1516599978, 1110731072, 1129994304, 1900969452,
1799645792, 1167997578, 2122946280, 1651418754, 2142158358, 1419457044, 1222166472, 2003699382, 1389200150, 1343114078, 1693518732, 2138347188, 1765688034, 2020934318, 1285195728, 1852141220, 1744573662, 1961696714, 1997454308, 1849035144,
1634842334, 1543074620, 1114779578, 1793351394, 1134944850, 1318397352, 1967496998, 1205628440, 1309822824, 1253566430, 1205930838, 1084372242, 1267943732, 1462978710, 1277098638, 1795576892, 1110859200, 1306136880, 1359665810, 2026161792,
2011009538, 1106001390, 1814004014, 1610355624, 1350583280, 2101692434, 1821768954, 2054368038, 1787568794, 1222742954, 1770935460, 1818437078, 1737930632, 1947444660, 1256588990, 1290166764, 1133279310, 1373538834, 1643045942, 1235802210,
1648072650, 1108542584, 1587407832, 1375644182, 1789033838, 1616174744, 1625603930, 1840040492, 1584062108, 1912937358, 1143485700, 1765230830, 2059611630, 1150957778, 1918104432, 1348732460, 1837159274, 1287371018, 1674327104, 1144868828,
1165991790, 1509919838, 1374629060, 1288880310, 2009797788, 1247808432, 1411793634, 2145590022, 1327468482, 1257647204, 1938196260, 1837091918, 1974544700, 1384768580, 1567038714, 1682493434, 1534513452, 1428521604, 1670684154, 1199936532,
1089688232, 1819052900, 2094417360, 1944639450, 1626426410, 1178881190, 1789020812, 1299666510, 2007580052, 1935401918, 1434139320, 1731293918, 1881112074, 1335517664, 2017997954, 1775491382, 1283547818, 1430435828, 1317776378, 1289542998,
2069322744, 1860481808, 1163219172, 1542447872, 1452104762, 1961260844, 1868640210, 1287464198, 1445999880, 1585663532, 1182000162, 2010235038, 1635109104, 1751328194, 1991436750, 1811049830, 1885574850, 1946730594, 1692249314, 1143236904,
1959517604, 1098397148, 2088098330, 2030116022, 1457975942, 2069453342, 1274504082, 1710377562, 1564749930, 1641886482, 2143073378, 1476753870, 1778904708, 1842435174, 1860438440, 1831206608, 2079157430, 1243919918, 1949582210, 1923966128,
1297423820, 1514806730, 1880411624, 1991508180, 1270978074, 1447155020, 1742410820, 1841761994, 1505484600, 1674006042, 1729303062, 1827050648, 1512855974, 2091875988, 1221971438, 1413515294, 1558854570, 1580584770, 1414373382, 2070919224,
1242118514, 1267639914, 1110683174, 1965491982, 1396872888, 1232474564, 2023900142, 1396734800, 1381037388, 1579521608, 1989068900, 1565198448, 1862266122, 1373153228, 2062302632, 1918540440, 1822504712, 1087652010, 1746669930, 1416311628,
1596716910, 1590180224, 1231186322, 1983978572, 1663674284, 1697932338, 2132215568, 1598151300, 1784291010, 2141353442, 1980010190, 1212964692, 1357168560, 1938223038, 1675824384, 1564634432, 1108834454, 1256318822, 1590890402, 1687609794,
1332236810, 2017109850, 1585106834, 2047338344, 1261435074, 1546466588, 1567508712, 2085221754, 1447478070, 1968178658, 1880060738, 1247615690, 1964853414, 1164037884, 2044476770, 1087306664, 1512490488, 1530941874, 1716717624, 1182068948,
1403322660, 1725778404, 2147270498, 1282111248, 1172414870, 1645118648, 1546425498, 2062629132, 1369015820, 1094942244, 1921330820, 1823157254, 2035654008, 2057277614, 1386622650, 2081025998, 1119544664, 1578137844, 2006926022, 1810329854,
1356728162, 1540791390, 1096264208, 1286607062, 1979943542, 1156822722, 1389265614, 2087642274, 1244744562, 2095199190, 1747451258, 1821096710, 1529904744, 1684571100, 1765456788, 1456285878, 2078819924, 1422687464, 2023653300, 1846280418,
2074963418, 2077779044, 1249949228, 1969623978, 1247579090, 1142226362, 1858518368, 1196593628, 1361721588, 1644779652, 1570627118, 1545616692, 1233509378, 1514268948, 1303412610, 1905876564, 1531990028, 2098643888, 2059929582, 2138626922,
1634697818, 1241751662, 1124839632, 1549516722, 1206585930, 1500232038, 1955608148, 1415117154, 1904064480, 1409762252, 2064202202, 1743462780, 2091702248, 1681395998, 1558652742, 2010017748, 1348074990, 1152812430, 1692301718, 2002391648,
1381075052, 1850998728, 1994946302, 1672148592, 1084437450, 1158792210, 1107484542, 1934683274, 1707383582, 1273059732, 1725578774, 1388362518, 1730414952, 2001751862, 1315543682, 1577911748, 1486005590, 1635309414, 1524912608, 1943523552,
1666348002, 1343674868, 1369367268, 1098295494, 1428102840, 1978924314, 1954827164, 1097392664, 1637052008, 2146585784, 1693699298, 2073826524, 1836675174, 1860595520, 1607945918, 1723364624, 2019077070, 2043222080, 1825671908, 2029716048,
1759072748, 1235693550, 1723203662, 1140570702, 2112046194, 1252413942, 2027066820, 2040324830, 2009552324, 1645067130, 1208540742, 1266230072, 1222902114, 1160934782, 1350408728, 1605841470, 1444085582, 1171267094, 1451644142]

for char,val in zip(chars,vals):
    if val % 2 == 1:
        print(chr(char),end="")
```
