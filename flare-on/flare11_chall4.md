Flare-On 11 <br>By DisplayGFX <br>Challenge 4:  Meme Maker 3000
===

Challenge Description:
```
You've made it very far, I'm proud of you even if noone else is. You've earned yourself a break with some nice HTML and JavaScript before we get into challenges that may require you to be very good at computers.
```

Oh boy, even just looking at the file size can make you nervous

```
$ ls -la          
-rwxrwxrwx 1 root root 2.4M Aug 12 09:42 mememaker3000.html
```

Looking at the source, it appears innocent for most lines, except for one.

```
<body>
    <h1>FLARE Meme Maker 3000</h1>

    <div id="controls">
        <select id="meme-template">
            <option value="doge1.png">Doge</option>
            <option value="draw.jpg">Draw 25</option>
            <option value="drake.jpg">Drake</option>
            <option value="two_buttons.jpg">Two Buttons</option>
            <option value="boy_friend0.jpg">Distracted Boyfriend</option>
            <option value="success.jpg">Success</option>
            <option value="disaster.jpg">Disaster</option>
            <option value="aliens.jpg">Aliens</option>
        </select>
        <button id="remake">Remake</button>
    </div>

    <div id="meme-container">
        <img id="meme-image" src="" alt="">
        <div id="caption1" class="caption" contenteditable></div>
        <div id="caption2" class="caption" contenteditable></div>
        <div id="caption3" class="caption" contenteditable></div>
    </div>
    <script>[Giant, scary looking block of javascript]
    </script>
</body>
</html>
```

Well, whenever there is javascript, the first thing is to run it through a deobfscator. I used https://deobfuscate.io/

However, that still leaves a LOT to be desired.

From here, there are two ways of proceeding. One I did while the competition was ongoing, and one afterwards.

# Javascript Dynamic Analysis

From here, if you look at the script, you will notice these lines at the end of the script
```
a0l['addEve' + a0p(0x17372) + 'ener']('keyup', () => {
    a0k();
}), a0m[a0p(0xc784) + a0p(0x17372) + a0p(0x17e2f)](a0p(0xb6f5), () => {
    a0k();
}), a0n[a0p(0xc784) + a0p(0x17372) + a0p(0x17e2f)](a0p(0xb6f5), () => {
    a0k();
});
```

if you carefully observer, you will see `keyup` and what looks like `addEventListener`

What you can do is to set a breakpoint in firefox for events. set an event listener in the debugger for `keyup`, and look at what happens.

You will see a call to `a0k`, and that checks a few things.
```js
function a0k() {
  const t = a0p,
  a = a0g[t(2589)]['split']('/') [t(2024)]();
  if (a !== Object[t(22981)](a0e) [5]) return;
  const b = a0l['textCo' + 'ntent'],
  c = a0m[t(69466) + t(75179)],
  d = a0n['textCo' + 'ntent'];
  if (
    a0c[t(77091) + 'f'](b) == 14 &&
    a0c[t(77091) + 'f'](c) == a0c[t(87117)] - 1 &&
    a0c[t(77091) + 'f'](d) == 22
  ) {
    var e = new Date() [t(67914) + 'e']();
    while (new Date() [t(67914) + 'e']() < e + 3000) {
    }
    var f = d[3] + 'h' + a[10] + b[2] + a[3] + c[5] + c[c[t(87117)] - 1] + '5' + a[3] + '4' + a[3] + c[2] + c[4] + c[3] + '3' + d[2] + a[3] + 'j4' + a0c[1][2] + d[4] + '5' + c[2] + d[5] + '1' + c[11] + '7' + a0c[21][1] + b[t(89657) + 'e'](' ', '-') + a[11] + a0c[4][t(39554) + t(91499)](12, 15);
    f = f[t(82940) + t(35943)](),
    alert(
      atob(
        t(85547) + t(19490) + 'YXRpb2' + t(94350) + t(43672) + t(91799) + t(68036)
      ) + f
    );
  }
}
```

Helpfully, when coming to certain objects, or hovering over them, firefox will fill in the blanks, usually. Here are a few lines, deobfuscated. First, theres something that checks if its the 5th item in the list, and exits if its not. This is what the line really is.
```js
a =  document.getElementById("meme-image").alt.split("/").pop();
if (a !== Object["keys"](a0e)[5]) return;
```

So we know that the meme image must be 5, which if you enter `Object.keys(a0e)[5]` into the console, you get `boy_friend0.jpg`. Alright, this seems to be a hidden trigger for something, this must be the right path.

Next there's the if condition, which pulls from objects, and gets some item. here is the deobfuscated lines below.
```js
const b = document.getElementById("caption1").textContent;
const c = document.getElementById("caption2").textContent;
const d = document.getElementById("caption3").textContent;
if (
  a0c.indexOf(b) == 14 && 
  a0c.indexOf(c) == a0c.length - 1 && 
  a0c.indexOf(d) == 22
) {
```

So what are these in `a0c`? well, its a list, so simply running the console will be enough to get these lines.
```js
>> a0c[14]
"FLARE On"
>> a0c[22]
"Malware"
>> a0c[a0c.length-1]
"Security Expert" 
```

Well, it checks for these three. lets see what entering these in will lead to. `Security Expert` as the boyfriend, `Malware` as the girlfriend, and `FLARE On` as the hot girl.

You get the flag!

`Congratulations! Here you go: wh0a_it5_4_cru3l_j4va5cr1p7@flare-on.com`

# Deobfuscation

So, lets say you wanted to do this the hard way.

Well, I did it, so you dont have to!

There is one function to generally be aware of, `a0p`. This function eventually will return a valid string.

```js
const a0p = a0b;
(function(a, b) {
    const o = a0b,
        c = a();
    while (!![]) {
        try {
            const d = parseInt(o(0xd7ed)) / 0x1 * (parseInt(o(0x381d)) / 0x2) + -parseInt(o(0x10a7f)) / 0x3 * (-parseInt(o(0x15fd2)) / 0x4) + parseInt(o(0x128f8)) / 0x5 + -parseInt(o(0x1203c)) / 0x6 + parseInt(o(0xe319)) / 0x7 * (parseInt(o(0xe69f)) / 0x8) + -parseInt(o(0x17d84)) / 0x9 + parseInt(o(0x6866)) / 0xa * (-parseInt(o(0x2e3b)) / 0xb);
            if (d === b) break;
            else c.push(c.shift());
        } catch (e) {
            c.push(c.shift());
        }
    }
}(a0a, 0x56f9f));
```

While its neigh incomprehensible, it does return a string. But it also calls `a0b` while in there, and that's comprehendible for the human mind.

```js
function a0b(a, b) {
    const c = a0a();
    return a0b = function(d, e) {
        d = d - 0x1db;
        let f = c[d];
        return f;
    }, a0b(a, b);
}

function a0a() {
    const u = [snip]
    a0a = function() {
        return u;
    };
    return a0a();
}
```

`u` is so long, it causes my VSCode program to stutter when I scroll over it. But, point being, these three functions are enough to return valid strings.

Once you get into a rhythm, you can decode these without execution of the main code in about an hour or so. Look at `flare11_chall4.js`, there will be is the entire script deobfuscated and the obfuscation functions removed.

For now, lets re-examine `a0k` with the deobfuscated script.
```js
function secret_flag() {
  a =  document.getElementById("meme-image").alt.split("/").pop();
  if (a !== Object["keys"](images)[5]) return;
  const b = document.getElementById("caption1").textContent;
  const c = document.getElementById("caption2").textContent;
  const d = document.getElementById("caption3").textContent;
  if (
      meme_captions.indexOf(b) == 14 && 
      meme_captions.indexOf(c) == meme_captions.length - 1 && 
      meme_captions.indexOf(d) == 22
    ) {
    var e = (new Date).getTime();
    while ((new Date).getTime() < e + 3e3) {}
    var f = d[3] + "h" + a[10] + b[2] + a[3] + c[5] + c[c.length - 1] + "5" + a[3] + "4" + a[3] + c[2] + c[4] + c[3] + "3" + d[2] + a[3] + "j4" + meme_captions[1][2] + d[4] + "5" + c[2] + d[5] + "1" + c[11] + "7" + meme_captions[21][1] + b.replace(" ", "-") + a[11] + meme_captions[4].substring(12, 15);
    f = f.toLowerCase(), alert(atob("Q29uZ3JhdHVsYXRpb25zISBIZXJlIHlvdSBnbzog") + f);
  }
}

```

Here, it is obvious, it will look at the 3 captions, check if they are the correct ones, and make the flag from the strings contained in the captions and the captions bank. It also has an alert with an encoded string, `atob("Q29uZ3JhdHVsYXRpb25zISBIZXJlIHlvdSBnbzog")`. Turns out, this is base64. And it turns into `Congratulations! Here you go: `.  From here, you could open the page, or you could manually reconstruct the string yourself.


P.S.:

Someone afterwards told me about this website, which gets all of the javascript deobfuscation immediately.

https://deobfuscate.relative.im/

Damn...