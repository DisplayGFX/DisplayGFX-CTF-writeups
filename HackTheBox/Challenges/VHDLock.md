HTB Challenge

Opening up the zip file, we see two files.
`lock.vhd` and `out.txt`

Looking at `lock.vhd` file, we can see that it is a written file. This is a VHDL (hence the name) program file. [VHDL is a Hardware description language](https://en.wikipedia.org/wiki/VHDL). In other words, it describes the behavior of a given circuit. Lets go through each part, one by one

```vhdl
----------------------------------
-- first component for xor operation
----------------------------------
library ieee;
use ieee.std_logic_1164.all;

entity xor_get is
    port(input1,input2 : in std_logic_vector(15 downto 0);
        output : out std_logic_vector(15 downto 0));
    end xor_get;

architecture Behavioral of xor_get is
begin
    output <= input1 xor input2;
end Behavioral;
```

This describes a component that, essentially, XORs the inputs, and returns an output. More specifically, we can see with `std_logic_vector(15 downto 0)`, that it takes 16 bit inputs, and returns a 16 bit output. It is important to keep the bits in mind. Onward.

```vhdl
----------------------------------
-- second component for decoder 4x16
----------------------------------
library ieee;
use ieee.std_logic_1164.all;

entity decoder_4x16 is
    port(input : in std_logic_vector(3 downto 0);
        output : out std_logic_vector(15 downto 0));
    end decoder_4x16;

architecture Behavioral of decoder_4x16 is
begin
    process(input)
    begin
        case input is
            when "0000" => output <= "0000000000000001";
            when "0001" => output <= "0000000000000010";
            when "0010" => output <= "0000000000000100";
            when "0011" => output <= "0000000000001000";
            when "0100" => output <= "0000000000010000";
            when "0101" => output <= "0000000000100000";
            when "0110" => output <= "0000000001000000";
            when "0111" => output <= "0000000010000000";
            when "1000" => output <= "0000000100000000";
            when "1001" => output <= "0000001000000000";
            when "1010" => output <= "0000010000000000";
            when "1011" => output <= "0000100000000000";
            when "1100" => output <= "0001000000000000";
            when "1101" => output <= "0010000000000000";
            when "1110" => output <= "0100000000000000";
            when "1111" => output <= "1000000000000000";
            when others => output <= "0000000000000000";
        end case;
    end process;
end Behavioral;
```

With this component, it turns a `std_logic_vector(3 downto 0)` 4 bit input into a `std_logic_vector(15 downto 0)` 16 bit output. This is called [one-hot encoding](https://en.wikipedia.org/wiki/One-hot), where a value is represented as a 1 in a certain position. so a 1 in the 16th position represents a `1111` or 15 or (16-1). so if we need a 16 bit representation of a 4 bit number, this will deliver us the format that we need. You can see the combination above happening, which comes relevant in the code below.


```VHDL
----------------------------------
-- main component
----------------------------------
library ieee;
use ieee.std_logic_1164.all;

entity main is
    port(input_1,input_2 : in std_logic_vector(3 downto 0);
        xorKey : in std_logic_vector(15 downto 0);
        output1,output2 : out std_logic_vector(15 downto 0));
    end main;

architecture Behavioral of main is

    signal decoder1,decoder2: std_logic_vector(15 downto 0);
    component xor_get is
        port(input1,input2 : in std_logic_vector(15 downto 0);
            output : out std_logic_vector(15 downto 0));
        end component;
    component decoder_4x16 is
        port(input : in std_logic_vector(3 downto 0);
            output : out std_logic_vector(15 downto 0));
        end component;
            begin
                L0 : decoder_4x16 port map(input_1,decoder1);
                L1 : decoder_4x16 port map(input_2,decoder2);
                L2 : xor_get port map(decoder1,xorKey,output1);
                L3 : xor_get port map(decoder2,xorKey,output2);

        end Behavioral;
```

The first relevant part is that it takes in 3 things, `xorKey` which is 16 bits, `input_1` and `input_2` which are 4 bits, and returns `output1` and `output2`, which are also 16 bits.

moving on, we can see that `xor_get` and `decoder_4x16` are used in the code. After that, we can see the order to things. The inputs are passed through the decoder (turning them into 16 bit onehot numbers), and XOR'd with a `xorKey` to get our outputs.

After successfully understanding `lock.vhd`, lets turn our attention to `out.txt` and understand what it is.

What is easy to notice is that there are two numbers per line. The more relevant observation is that both of them are relatively similar most of the time, and both numbers never exceed 32700. This is important because 2^16 is 32,768. This must be the two 16 bit output numbers that was mentioned in the `lock.vhd`. 

So, here are the facts we know about the output numbers
1. both are XOR'd with a common `xorKey`
2. each input number to the `xor_get` is one-hot encoded
3. if we get the 16 bit one-hot number, we can get the original 4 bit number.
One apt description of XOR is that its a mask that will flip bits of the number that is put through it (with `xorKey` being the mask). 

So, if we compare the two output numbers in binary, it should be easy to pick out the same bits with only 2 bits of the two numbers being different from each other. 

example:
010000 XOR 110111 = 100111
000100 XOR 110111 = 110011

Its not evident with just 6 bits exactly what the mask should be, but it is very clear that there are many shared bits, and these should be part of the `xorKey`. 

So, applying this to the number, assuming they are 16 bits...

```
output1: 0000000000100011 output2: 0000000100110011
output1: 0000000000010001 output2: 0000000000100001
output1: 0000000000100001 output2: 0000000000110101
output1: 0000000010110111 output2: 0000100000110111
...
output1: 0000000010110111 output2: 0010000000110111
```

If you look through the bits, you can XOR the outputs together and get the altered bits, which should always be 2 or zero (if they are the same bit altered).

```
altBits: 0000000100010000
altBits: 0000000000110000
altBits: 0000000000010100
altBits: 0000100010000000
...
altBits: 0000000000000000
altBits: 0000000000000000
altBits: 0000000000000000
...
altBits: 0000000001100000
altBits: 0010000010000000
```

You could try from here to grab the decoded message, but its impossible to know which bit belongs to `decoder1` or `decoder2`. So, lets try to find the `xorKey`. If you look at the bits that do NOT change, you will notice a cyclical pattern.

```
output1: 0000000000100011 output2: 0000000100110011 altBits: 0000000100010000
output1: 0000000000010001 output2: 0000000000100001 altBits: 0000000000110000
output1: 0000000000100001 output2: 0000000000110101 altBits: 0000000000010100
output1: 0000000010110111 output2: 0000100000110111 altBits: 0000100010000000
output1: 0000000000100011 output2: 0000001000110011 altBits: 0000001000010000
output1: 0000000000010001 output2: 1000000000110001 altBits: 1000000000100000
output1: 0000000000100001 output2: 0001000000110001 altBits: 0001000000010000
output1: 0000000000111111 output2: 0000000000110110 altBits: 0000000000001001
output1: 0000000010110011 output2: 0000000001110011 altBits: 0000000011000000
output1: 0000000000111001 output2: 0000000000111001 altBits: 0000000000000000
output1: 0000000000010001 output2: 1000000000110001 altBits: 1000000000100000
output1: 0000000000010111 output2: 0000000001110111 altBits: 0000000001100000
output1: 0000000000100011 output2: 0000000100110011 altBits: 0000000100010000
output1: 0000000000100001 output2: 0000000000100001 altBits: 0000000000000000
output1: 0000000000100001 output2: 0001000000110001 altBits: 0001000000010000
```

it is much easier to tell with one-hot bits set like `output1: 0000000010110111 output2: 0000100000110111 altBits: 0000100010000000`.  There are enough high one-hot bit pairs for you to see that the XOR key rotates every 4 occurances. Which four numbers, I will leave as an exercise to the reader, but once you get the rotating `xorKey`, you should be left with just the one-hot encoded number.

```
decode1: 0000000000010000 decode2: 0000000100000000 
decode1: 0000000000100000 decode2: 0000000000010000 
decode1: 0000000000010000 decode2: 0000000000000100 
decode1: 0000000010000000 decode2: 0000100000000000 
```

Decode the one-hot encoding, which should be as simple as counting how far along the number is, and you get.
```
decode1: 0000000000010000 decode2: 0000000100000000 
input1: 4 input2: 8 
input1: 0100 input2: 1000 
decode1: 0000000000100000 decode2: 0000000000010000 
input1: 5 input2: 4 
input1: 0101 input2: 0100 
decode1: 0000000000010000 decode2: 0000000000000100 
input1: 4 input2: 2 
input1: 0100 input2: 0010 
decode1: 0000000010000000 decode2: 0000100000000000 
input1: 7 input2: 11 
input1: 0111 input2: 1011 
```
something tells me this is ASCII!
```
input1: 0100 input2: 1000 
H
input1: 0101 input2: 0100 
T
input1: 0100 input2: 0010 
B
input1: 0111 input2: 1011 
{
```

And this gives you the flag!

https://www.hackthebox.com/achievement/challenge/158887/468