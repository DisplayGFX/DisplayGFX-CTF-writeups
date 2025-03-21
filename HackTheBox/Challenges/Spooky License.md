Spooky License
===

HTB Challenge

By DisplayGFX
___
Description
```
After cleaning up we found this old program and wanted to see what it does, but we can't find the licence we had for it anywhere. Can you help?
```

It seems the only file provided is `spookylicence`. 

## Initial Enumeration

It is an executable, so lets take a look at how it works
```zsh
$ ./spookylicence 
./spookylicence <license>
$ ./spookylicence helloworld
Invalid License Format
$ ./spookylicence helloworlddddddddddddddddddddddd
License Invalid
```

Nothing much informative, so lets take a look at it in ghidra.

So, entry seems to point to a function, and most functions seemed to be stripped of their name, so lets take a look at `FUN_00101169`. 
```c
undefined8 FUN_00101169(int param_1,char **param_2)

{
  char *pcVar1;
  undefined8 uVar2;
  size_t sVar3;
  
  if (param_1 == 2) {
    sVar3 = strlen(param_2[1]);
    if (sVar3 == 0x20) {
      pcVar1 = param_2[1];
      if ((((((((pcVar1[0x1d] == (char)((pcVar1[5] - pcVar1[3]) + 'F')) &&
               ((char)(pcVar1[2] + pcVar1[0x16]) == (char)(pcVar1[0xd] + '{'))) &&
              ((char)(pcVar1[0xc] + pcVar1[4]) == (char)(pcVar1[5] + '\x1c'))) &&
             ((((char)(pcVar1[0x19] * pcVar1[0x17]) == (char)(*pcVar1 + pcVar1[0x11] + '\x17') &&
               ((char)(pcVar1[0x1b] * pcVar1[1]) == (char)(pcVar1[5] + pcVar1[0x16] + -0x15))) &&
              (((char)(pcVar1[9] * pcVar1[0xd]) == (char)(pcVar1[0x1c] * pcVar1[3] + -9) &&
               ((pcVar1[9] == 'p' &&
                ((char)(pcVar1[0x13] + pcVar1[0x15]) == (char)(pcVar1[6] + -0x80))))))))) &&
            (pcVar1[0x10] == (char)((pcVar1[0xf] - pcVar1[0xb]) + '0'))) &&
           (((((((char)(pcVar1[7] * pcVar1[0x1b]) == (char)(pcVar1[1] * pcVar1[0xd] + '-') &&
                (pcVar1[0xd] == (char)(pcVar1[0x12] + pcVar1[0xd] + -0x65))) &&
               ((char)(pcVar1[0x14] - pcVar1[8]) == (char)(pcVar1[9] + '|'))) &&
              ((pcVar1[0x1f] == (char)((pcVar1[8] - pcVar1[0x1f]) + -0x79) &&
               ((char)(pcVar1[0x14] * pcVar1[0x1f]) == (char)(pcVar1[0x14] + '\x04'))))) &&
             ((char)(pcVar1[0x18] - pcVar1[0x11]) == (char)(pcVar1[0x15] + pcVar1[8] + -0x17))) &&
            ((((char)(pcVar1[7] + pcVar1[5]) == (char)(pcVar1[5] + pcVar1[0x1d] + ',') &&
              ((char)(pcVar1[0xc] * pcVar1[10]) == (char)((pcVar1[1] - pcVar1[0xb]) + -0x24))) &&
             ((((char)(pcVar1[0x1f] * *pcVar1) == (char)(pcVar1[0x1a] + -0x1b) &&
               ((((char)(pcVar1[1] + pcVar1[0x14]) == (char)(pcVar1[10] + -0x7d) &&
                 (pcVar1[0x12] == (char)(pcVar1[0x1b] + pcVar1[0xe] + '\x02'))) &&
                ((char)(pcVar1[0x1e] * pcVar1[0xb]) == (char)(pcVar1[0x15] + 'D'))))) &&
              ((((char)(pcVar1[5] * pcVar1[0x13]) == (char)(pcVar1[1] + -0x2c) &&
                ((char)(pcVar1[0xd] - pcVar1[0x1a]) == (char)(pcVar1[0x15] + -0x7f))) &&
               (pcVar1[0x17] == (char)((pcVar1[0x1d] - *pcVar1) + 'X'))))))))))) &&
          (((pcVar1[0x13] == (char)(pcVar1[8] * pcVar1[0xd] + -0x17) &&
            ((char)(pcVar1[6] + pcVar1[0x16]) == (char)(pcVar1[3] + 'S'))) &&
           ((pcVar1[0xc] == (char)(pcVar1[0x1a] + pcVar1[7] + -0x72) &&
            (((pcVar1[0x10] == (char)((pcVar1[0x12] - pcVar1[5]) + '3') &&
              ((char)(pcVar1[0x1e] - pcVar1[8]) == (char)(pcVar1[0x1d] + -0x4d))) &&
             ((char)(pcVar1[0x14] - pcVar1[0xb]) == (char)(pcVar1[3] + -0x4c))))))))) &&
         (((char)(pcVar1[0x10] - pcVar1[7]) == (char)(pcVar1[0x11] + 'f') &&
          ((char)(pcVar1[1] + pcVar1[0x15]) == (char)(pcVar1[0xb] + pcVar1[0x12] + '+'))))) {
        puts("License Correct");
        uVar2 = 0;
      }
      else {
        puts("License Invalid");
        uVar2 = 0xffffffff;
      }
    }
    else {
      puts("Invalid License Format");
      uVar2 = 0xffffffff;
    }
  }
  else {
    puts("./spookylicence <license>");
    uVar2 = 0xffffffff;
  }
  return uVar2;
}
```

Oh dear. Looking at.... something other than that, this function appears to be all the program. We can verify this by jumping to the other functions, and seeing that they are either called by entry or exit functions while not doing to much consequential things themselves. 

On line 48, line 53 and line 58, there are the `puts` statements we saw earlier. Of note, we can see that the key needs to be `0x20` bytes long. And on line 44 is our desired destination. And the huge block of `if` and `boolean` comparison statements.

There are two ways to approach this problem. There's the hard way, where if inclined you can untie the Gordian knot of the conditional statements. This would be long, tedious, and no guarantee you get the desired answer.
## Symbolic Execution

Or.... You can do [symbolic execution](https://en.wikipedia.org/wiki/Symbolic_execution). Read the wikipedia article if you care for more details, but its looking at the program to see what inputs leads to what actions in the program. Our case, we want our symbolic execution to guide us to the puts function call that prints "License Correct".

Python has a symbolic execution library called [`angr`](https://angr.io/).

>angr is an open-source binary analysis platform for Python. It combines both **static and dynamic symbolic ("concolic") analysis**, providing tools to solve a variety of tasks.

Emphasis mine. 

This is exactly what we are looking for. [Here](https://docs.angr.io/en/latest/core-concepts/toplevel.html) is where we start to develop our symbolic analysis of the program.

>Your first action with angr will always be to load a binary into a project

```python
import angr
p = angr.Project('./spookylicence')
```

The article goes on to talk about a factory needed for most `angr` functions and capabilities. so lets make an entry state. 
```python
st = p.factory.entry_state()
```
However, we need to set our arguments, as that is the important part of our program, remember that our flag is a specified length `0x20`, so we can incorporate all possibilites in what the article calls a `bitvector`, which represents all of the possible bits states that the given object could be in for a given length.

[This article goes into more detail about states](https://docs.angr.io/en/latest/core-concepts/states.html), but the short of it is to make a bitvector that represents the possible flag.
```python
#we need to keep this factory variable around, else python will throw errors
f = p.factory.entry_state()
flag = f.solver.BVS('arg',8*0x20)
#This can be substituted with another library called claripy, which gives us bitvectors without spawning a factory
import claripy
flag = claripy.BVS('arg' , 8*0x20)
```
We multiply `0x20` by 8 to represent each character as a byte.

`flag` needs to be fed in as an argument, so we create our intended entry_state with the `args` parameter. Then, we start up our program with the simulation_manager to get our program running. Article about it [here](https://docs.angr.io/en/latest/core-concepts/pathgroups.html)
```python
st = p.factory.entry_state(args=['./spookylicence', flag])
sm = p.factory.simulation_manager(st)
```

In order to get to our desired state, we need to locate where it is. Going to ghidra, we can determine the offset, `0x187d`. The base address we can assume is `0x400000` from [this article](https://docs.angr.io/en/latest/core-concepts/loading.html).
```python
find = 0x400000+0x187d
sm.explore(find=find)
```

Once we have executed the above line, we can use these next two lines for a "solution" to our program.
```python
found = sm.found[0]
print(found.solver.eval(flag, cast_to=bytes))
```

This works, and gets the flag.

https://www.hackthebox.com/achievement/challenge/158887/409

However, there are a few issues we can see and resolve.

```zsh
$ python3 spookysolve.py
WARNING  | 2024-02-27 14:34:49,316 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing memory with an unspecified value. This could indicate unwanted behavior.   
WARNING  | 2024-02-27 14:34:49,317 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:   
WARNING  | 2024-02-27 14:34:49,317 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state                                                          
WARNING  | 2024-02-27 14:34:49,317 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null             
WARNING  | 2024-02-27 14:34:49,317 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppress these messages.                 
WARNING  | 2024-02-27 14:34:49,317 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7ffffffffff0000 with 49 unconstrained bytes referenced from 0x59e4c0 (strlen+0x0 in libc.so.6 (0x9e4c0))
[flag]
```

to solve the errors, we add to the entry state as below
```python
st = p.factory.entry_state(args=['./spookylicence', flag], add_options={
    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
})
```

However, there's still the issue of performance. if we add an avoid state, which should only be the `License Invalid`, we can speed up execution of the solve script. Or at least, we can more explicitly define states that should be avoided, more important for larger programs.
```python
find = 0x400000+0x187d
avoid = 0x400000+0x1890
sm.explore(find=find, avoid=avoid)
```