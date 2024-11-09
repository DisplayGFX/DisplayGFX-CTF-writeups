Flare-On 11 <br>By DisplayGFX <br>Challenge 1: frog 
===

Challenge Description:
```
Welcome to Flare-On 11! Download this 7zip package, unzip it with the password 'flare', and read the README.txt file for launching instructions. It is written in PyGame so it may be runnable under many architectures, but also includes a pyinstaller created EXE file for easy execution on Windows.

Your mission is get the frog to the "11" statue, and the game will display the flag. Enter the flag on this page to advance to the next stage. All flags in this event are formatted as email addresses ending with the @flare-on.com domain.
```


This challenge went by relatively quickly, its just meant as a poll to see how many active users were attempting the Flare-On challenge.

When extracting the archive, you will immediately notice `frog.py`.

There are two ways to solve this challenge. Engage with the python script, or realize theres a `GenerateFlagText` function.

```python
def GenerateFlagText(x, y):
    key = x + y*20
    encoded = "\xa5\xb7\xbe\xb1\xbd\xbf\xb7\x8d\xa6\xbd\x8d\xe3\xe3\x92\xb4\xbe\xb3\xa0\xb7\xff\xbd\xbc\xfc\xb1\xbd\xbf"
    return ''.join([chr(ord(c) ^ key) for c in encoded])
```

Its used here
```python
if player.x == victory_tile.x and player.y == victory_tile.y:
	victory_mode = True
	flag_text = GenerateFlagText(player.x, player.y)
```

And `victory_tile` is set here
```python
victory_tile = pygame.Vector2(10, 10)
```

So, the XOR key is `210`, or `0xd2`. Using this to xor `encoded` gives you the flag

`welcome_to_11@flare-on.com`