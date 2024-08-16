This challenge has nothing to download, only a IP and port to connect to.
Connecting to it gives this
```bash
nc 94.237.54.75 34546        

#####################################################################                               
#                                                                   #                               
# I told you not to fall asleep!                                    #                               
#                                                                   #                               
# A 500 question quiz is coming up.                                 #                               
#                                                                   #                               
# Be careful; Dream math works a little differently:                #                               
# Addition and multiplication have the REVERSE order of operation.  #                               
#                                                                   #                               
# And remember, if you fail in your sleep, you fail in real life... #                               
#                                                                   #                               
#####################################################################                               
                                                                                                    
                                                                                                    
[001]: 58 + 46 * 49 * (89 * 76 * 10) + 56 * 63 * 49 * 60 = ?                                        
> 58 
Time ran out! You need practice!   
```
Clearly we need to automate this

So, pwntools to the rescue!

First, we need to connect, and grab a line from the connection. Pwntools has a nifty tool that allows us to connect with a single line
```python
import pwn
# must have ssh/nc creds
p = pwn.connect("94.237.54.75", 34546)
```
Then, lets grab lines until we get our first math equation. Looking at the output, it seems that we can grab the current number by waiting until `]` appears, after taking in a few lines to let the program start. We can use a similar method to get the equation as well, by just taking in the rest of the line, and using array on the resultant string to cut out the unneeded symbols and space.
```python
p.recvline()
p.recvuntil(b'[')
#gets current number question
number = p.recvuntil(b']')[5:8]
#gets math equation needed to be solved
line = p.recvline()[2:-5]
```

After this, a function will seem most useful, so lets make one, and give it the equation
```python
equation_solve(str(line))
```

First, we need to solve the equations inside parenthesis, going with normal order of operations. If there is more than one level of parenthesis, we need to solve those inside similarly. This calls for recursion.
```python
start = None
depth = 0
for i, char in enumerate(input):
	if char == '(':
		if start is None:
			start = i
			depth += 1
		elif char == ')':
			depth -= 1
			#top level of parenthesis check
			if depth == 0 and start is not None:
			inner_eq = input[start+1:i]
			#solve inside math
			solve = equation_solve(inner_eq)
			input_eq = input[:start] + str(solve) + input[i+1:]
			#solve resultant
			return equation_solve(input_eq)

if depth > 0:

raise ValueError("Unbalanced parentheses detected.")
```

This will check for the outermost parenthesis, call equation_solve on it, then conjoin the rest of the equation onto the result, and then call the function again, as if it was the original equation. this happens every time there is a parenthesis until either there is a mismatch between the parenthesis, or there are no more. This becomes a familiar pattern.


Okay, lets move on. we have "solved" all of the parenthetical equations, now is just the base. according to the challenge, we need to addition first. And so the issue becomes... how do we collect the numbers, and just the numbers? lets focus on the operator.

We know the operator is between two numbers, so we can base our offset from that. theres also a space inbetween the operator and the numbers on each side. and, on the far side of each number relative to the operator, we know theres either a space, or we reach the beginning/end of the number. With these constraints now made explicit, lets make our loop.

First, we loop through our string until we encounter an operator character.
```python
for i, char in enumerate(input):
	if char == '+':
```

Then, for our left number, we make another loop that starts on the first integer of the character, and keeps going until it hits the beginning of the function. Then, we detect if it has hit the beginning, or a space which indicates the end of a number.
```python
for x in range(i-2,-1,-1): # starts at the first number, or should
	if x == 0:
		break

	if input[x] == ' ':
		break
```

If in the first case we reach the beginning, we set the index of the left number to where it begins, and grab the string until the end of the number.
```python
if x == 0:
	left = int(input[:i-1])
	l_i = 0
	break
```

Then, the next case, if we find a space on the far side of the integer, we grab the input from the current x value to the operator minus one to get rid of extra spaces.
```python
if input[x] == ' ':
	l_i = x+1
	left = int(input[l_i:i-1])
	break
```

we do something very similar for the right number, except when grabbing, we grab with operator index + 2, because of exclusive indexing vs inclusive indexing.
```python
for y in range(i+2,len(input)):
	if y == len(input)-1:
		r_i = len(input)
		right = int(input[i+2:])
		break
	if input[y] == ' ':
		r_i = y
		right = int(input[i+2:y])
		break
```

At last, we add the two numbers together, and do a similar conjoining with the other sides of the equation, then feed this into the function yet again. This is made easy thanks to collecting the indexes in the above steps.
```python
new_input = input[:l_i] + str(left*right) + input[r_i:]
return equation_solve(new_input)
```

Same thing is done with the multiplier operator. After this is accomplished, we simply return the input, as if it gets to the end of both for loops, there are no more operators in the equation.

after this, our function should return the answer, and we simply have to send whatever equation_solve returned
```python
p.recvline()
p.recvuntil(b'[')
number = p.recvuntil(b']')[5:8].decode('utf-8')
line = p.recvline()[2:-5]
result = equation_solve(line.decode('utf-8'))
p.recvuntil(b'>')
p.sendline(bytes(result,'utf-8'))
```

this gets us...
```zsh
$ ./attack.py
 [002]: 23 * 73 * 53 * 99 * 16 = ?
> $ 
```

Now, all we need to do is send it 499 more times.
```python
.recvline()
p.recvuntil(b'[')
number = p.recvuntil(b']')[5:8].decode('utf-8')
print(number,sep='',end='\r')
for x in range(0,499):
    #gets current number question
    #gets math equation needed to be solved
    line = p.recvline()[2:-5]
    result = equation_solve(line.decode('utf-8'))
    p.recvuntil(b'>')
    p.sendline(bytes(result,'utf-8'))
    number = p.recvuntil(b']')[2:5].decode('utf-8')
    print(number,sep='',end='\r')
line = p.recvline()[2:-5]
result = equation_solve(line.decode('utf-8'))
p.recvuntil(b'>')
p.sendline(bytes(result,'utf-8'))
p.interactive()
```

And that should return us our flag.
```zsh
$ ./attack.py
...
 Well done! Here's the flag: HTB{fake_flag}
```

https://www.hackthebox.com/achievement/challenge/158887/445