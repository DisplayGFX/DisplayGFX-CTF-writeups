Pedometer
===

HTB Challenge

By DisplayGFX
___
Description
```
I've been using this pedometer app for weeks, and I am convinced it's using me as a power supply for some hidden machine. I bet it holds the key or a map to some sort of treasure. If only I could figure out what it's doing...
```

There is one file, `pedometer.apk`
## Initial Enumeration

This `.apk` file is an android program, so clearly, it calls for the tool `jadx-gui`

in `jadx`, we can see a `MainActivity`. Also worth noting, `jadx` is renaming function that are obscured by the original package. I will alternate between the names, and include the comments showing what it was originally named.

```java
public final void onCreate(Bundle bundle) {
	super.onCreate(bundle);
	setContentView(R.layout.activity_main);
	C0041d m63c = this.f73i.m63c("activity_rq#" + this.f72h.getAndIncrement(), this, new C0306c(0), new C0611a(this));
	if (AbstractC0955e.m2234a(this, "android.permission.ACTIVITY_RECOGNITION") == 0) {
		m997n(); //interesting func
	} else {
		m63c.m60w1(); //errors out
	}
	this.f1815v = new C0976c(this);
}
```

This function runs on creation, and seems to be normal, and checks if the app is given the `ACTIVITY_RECOGNITION` permission is given to it. Its not worth much more to analyze what the java code does.

```java
/* renamed from: n */
public final void m997n() {
	Object systemService = getSystemService("sensor");
	AbstractC1073e.m2489w(systemService, "null cannot be cast to non-null type android.hardware.SensorManager");
	SensorManager sensorManager = (SensorManager) systemService;
	this.f1814u = sensorManager;
	Sensor defaultSensor = sensorManager.getDefaultSensor(1);
	SensorManager sensorManager2 = this.f1814u;
	if (sensorManager2 != null) {
		//custom listener registered, names obscured
		sensorManager2.registerListener(new C0974a(this), defaultSensor, 3);
	} else {
		C1030d c1030d = new C1030d("lateinit property sensorManager has not been initialized");
		AbstractC1073e.m2441c1(c1030d);
		throw c1030d;
	}
}
```

In short, the function gets the sensor object for an accelerometer (via `getDefaultSensor(1)`) and then registers a listener if able, using another obscured class. So what is this class?

```java
/* renamed from: u1.a */
/* loaded from: classes.dex */
public final class C0974a implements SensorEventListener {

    /* renamed from: a */
    public final MainActivity f4054a;

    /* renamed from: b */
    public int f4055b;

    /* renamed from: c */
    public long f4056c;

    public C0974a(MainActivity mainActivity) {
        AbstractC1073e.m2493y(mainActivity, "activity");
        this.f4054a = mainActivity;
    }

    @Override // android.hardware.SensorEventListener
    public final void onAccuracyChanged(Sensor sensor, int i3) {
    }

...
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final void onSensorChanged(android.hardware.SensorEvent r9) {
        /*
            Method dump skipped, instructions count: 506
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: p070u1.C0974a.onSensorChanged(android.hardware.SensorEvent):void");
    }
}
```

wow, jadx seems to have difficulty disassembling this class. So, there are a few options. you can try another tool, but none I saw seemed to work, only producing java bytecode. however, jadx also has whats called `smali`, which is essentially java bytecode.

From this, there are a few ways of tackling the challenge. I chose to drop the bytecode into chatgpt, and ask it to reconstruct the equivalent. Here is what I got
```java
    @Override
    public void onSensorChanged(SensorEvent event) {
        long currentTime = Calendar.getInstance().getTimeInMillis();
        // Only process if at least 300ms have passed.
        if (currentTime - lastUpdateTime > 300) {
            lastUpdateTime = currentTime;
            
            // Process sensor value (likely from a pedometer)
            int sensorVal = (int) event.values[0];
            if (Math.abs(sensorVal) > 6) {
                stepCount++;
                // Update a TextView with the new step count.
                TextView stepView = (TextView) mainActivity.findViewById(0x7f0801a4); // resource ID from smali
                stepView.setText(String.valueOf(stepCount));
            }
            
            // Retrieve the VM (assumed to be stored in mainActivity.stepReader)
            C0976c vm = mainActivity.stepReader;
            if (vm == null) {
                throw new RuntimeException("lateinit property stepReader has not been initialized");
            }
            
            try {
                InputStream is = vm.inputStream;
                if (is.available() != 0) {
                    // Read a byte and decode it using the current encryption key.
                    int rawByte = is.read();
                    int instructionCode = rawByte ^ vm.encryptionKey;
                    
                    // Look up the matching opcode
                    EnumC0975b[] opcodes = EnumC0975b.values();
                    EnumC0975b instr = null;
                    for (EnumC0975b op : opcodes) {
                        if (op.opcode == instructionCode) {
                            instr = op;
                            break;
                        }
                    }
                    if (instr == null) {
                        throw new NoSuchElementException("Array contains no element matching the predicate.");
                    }
                    
                    // Execute the instruction based on its type.
                    switch (instr) {
                        case STOP:
                            // Stop execution (details omitted)
                            break;
						... cases
						
                        case FLAG:
                            // Flag-setting or similar operation.
                            // [FLAG implementation...]
                            break;
                        default:
                            break;
                    }
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
    
    // Helper: pop an integer from the VM's stack.
    private int popInt(C0976c vm) {
        return vm.popStack();
    }
}

``` 

Where do the cases come from? well, it comes from this class, again reconstructed from chatgpt

```java
package p070u1;

public enum EnumC0975b {
    STOP(0),
    PUSH(1),
    POP(2),
    ADD(0x10),
    SUB(0x11),
    MUL(0x12),
    DIV(0x13),
    MOD(0x14),
    EQ(0x20),
    LT(0x21),
    GT(0x22),
    NOT(0x30),
    XOR(0x31),
    IF(0x40),
    JMP(0x41),
    CHRG(0xF0),
    AIRPLN(0xF1),
    INTRNT(0xF2),
    ENC(0xF3),
    DEC(0xF4),
    FLAG(0xFF);

    // Each enum constant holds its associated opcode.
    public final int opcode;

    private EnumC0975b(int opcode) {
        this.opcode = opcode;
    }
}
```

The last question is where it loads the data from? there is a third class, thankfully not obscured to kingdom come.

```java
package p070u1;

import com.rloura.pedometer.MainActivity;
import java.io.InputStream;
import java.util.Stack;
import p079x1.AbstractC1073e;

/* renamed from: u1.c */
/* loaded from: classes.dex */
public final class C0976c {

    /* renamed from: a */
    public final MainActivity f4059a;

    /* renamed from: b */
    public final InputStream f4060b;

    /* renamed from: c */
    public final Stack f4061c;

    /* renamed from: d */
    public int f4062d;

    public C0976c(MainActivity mainActivity) {
        AbstractC1073e.m2493y(mainActivity, "main");
        this.f4059a = mainActivity;
        InputStream open = mainActivity.getAssets().open("a");
        AbstractC1073e.m2491x(open, "main.assets.open(\"a\")");
        this.f4060b = open;
        this.f4061c = new Stack();
    }

    /* renamed from: a */
    public final int m2264a() {
        Stack stack = this.f4061c;
        Integer num = (Integer) stack.peek();
        stack.pop();
        AbstractC1073e.m2491x(num, "value");
        return num.intValue();
    }
}
```

and checking within `assets/a` is a file that is only a couple dozen bytes long.
```
00000000: 0101 0100 0101 0101 0101 0101 0101 0101  ................
00000010: f020 4000 f120 4000 f220 4000 f020 4000  . @.. @.. @.. @.
00000020: 012a f32b 602b 1d1b 7c56 7c22 4c75 3875  .*.+`+..|V|"Lu8u
00000030: 0845 3131 3141 0171 8971 fa41 7209 7256  .E111A.q.q.Ar.rV
00000040: 425e 965e de6e 494d 4928 7964 dd64 a954  B^.^.nIMI(yd.d.T
00000050: 7575 752a 455e ca5e b96e 72c8 7283 424a  uuu*E^.^.nr.r.BJ
00000060: d54a a77a 7311 7325 4335 9135 fc05 6c0d  .J.zs.s%C5.5..l.
00000070: 6c52 5c5e 615e 396e 5972 5909 697a 537a  lR\^a^9nYrY.izSz
00000080: 114a 4359 430d 7355 bd55 f565 bcff 00    .JCYC.sU.U.e...
```
## Emulation

So, like with all VM challenges, I emulated the challenge.
```python
instruction_dict = {
    0x00: "STOP",
    0x01: "PUSH",
    0x02: "POP",
    0x10: "ADD",
    0x11: "SUB",
    0x12: "MUL",
    0x13: "DIV",
    0x14: "MOD",
    0x20: "EQ",
    0x21: "LT",
    0x22: "GT",
    0x30: "NOT",
    0x31: "XOR",
    0x40: "IF",
    0x41: "JMP",
    0xF0: "CHRG",
    0xF1: "AIRPLN",
    0xF2: "INTRNT",
    0xF3: "ENC",
    0xF4: "DEC",
    0xFF: "FLAG"
}


with open("./assets/a","rb") as x:
    byteprog = x.read()

byteprog = bytearray(byteprog)

#stack is seperate entity
stack = []

xorval = 0
x = 0
while True:
    
    if x >= len(byteprog):
        break
    byteread = byteprog[x] ^ xorval
    x += 1
    print(f"Stack {stack}")
    print(f"Instruction: {instruction_dict[byteread]} ", end='')

    match(byteread):
        case 0x0:  #STOP
            #In java, this is represented by skipping to the end of the program
            #in effect, just exit out of loop
            print()
            break
        case 0x1:  #PUSH
            pushVal = xorval ^ byteprog[x]
            x += 1 #readbyte from program
            assert type(pushVal) == int, f"pushval is not an int, type {type(pushVal)}"
            stack.append(pushVal )
            print(hex(pushVal))
        case 0x2:  #POP
            stack.pop() 
            print()
        case 0x10: #ADD
            a = stack.pop() 
            b = stack.pop() 
            stack.append((a+b))
            print(f"{a} + {b} = {a+b}")
        case 0x11: #SUB
            a = stack.pop() 
            b = stack.pop() 
            stack.append((a-b))
            print(f"{a} - {b} = {a-b}")
        case 0x12: #MUL
            a = stack.pop() 
            b = stack.pop() 
            stack.append((a*b))
            print(f"{a} * {b} = {a*b}")
        case 0x13: #DIV
            a = stack.pop() 
            b = stack.pop() 
            stack.append((a//b))
            print(f"{a} / {b} = {a//b}")
        case 0x14: #MOD
            a = stack.pop() 
            b = stack.pop() 
            stack.append((a%b))
            print(f"{a} % {b} = {a%b}")
        case 0x20: #EQ
            a = stack.pop() 
            b = stack.pop() 
            if a == b:
                stack.append(1)
            else:
                stack.append(0)
            print(f"{a} == {b} : {a == b}")
        case 0x21: #LT
            a = stack.pop() 
            b = stack.pop() 
            if a < b:
                stack.append(1)
            else:
                stack.append(0)
            print(f"{a} < {b} : {a < b}")
        case 0x22: #GT
            a = stack.pop() 
            b = stack.pop() 
            if a > b:
                stack.append(1)
            else:
                stack.append(0)
            print(f"{a} > {b} : {a > b}")
        case 0x30: #NOT
            raise NotImplementedError
            print()
        case 0x31: #XOR
            a = stack.pop()
            b = stack.pop()
            xorval = a^b
            stack.append((a^b))
            print(f"{a} ^ {b} = {hex(a ^ b)} : {chr(a^b)}")
        case 0x40: #IF
            a = stack.pop() 
            if a == 1:
                b = stack.pop() 
                x += b #skip certain amount
            print(f"if {a} == 1, jmp {b} : " + "jumped" if a == 1 else "not jumped")
        case 0x41: #JMP
            a = stack.pop() 
            x += a #skips certain amount
            print(f"{b}")
        case 0xf0: #CHRG
            #return value it expects
            y = stack.pop()
            stack.append(y)
            stack.append(y)
            pass #check if its being charged? 
            # push 1 if so, 0 if not
            print(f"expected value: {y }")
        case 0xf1: #AIRPLN
            #return value it expects
            y = stack.pop()
            stack.append(y)
            stack.append(y)
            pass #check if in airplane mode?
            # push 1 if so, 0 if not
            print(f"expected value: {y }")
        case 0xf2: #INTRNT
            #return value it expects
            y = stack.pop()
            stack.append(y)
            stack.append(y)
            pass #something something check if connected
            # push 1 if so, 0 if not
            print(f"expected value: {y }")
        case 0xf3: #ENC
            xorval = stack.pop() #sets the xor key
            print(f"changed to {xorval}")
        case 0xf4: #DEC
            xorval = 0
            print()
        case 0xff: #FLAG
            for x in stack[::-1]:
                print(chr(x),end='')
            #prints out string from stack
        case _:
            raise NotImplementedError
    input()
```

A few things worth noting for the emulation.
- when the XOR key is set, everything from the instruction set is XORed with the key. however, the stack is kept clean.
- the XOR key is set two different ways, either with `ENC`/`DEC` which starts and ends the encryption; and `XOR`, which takes the top two values from the stack, XORs them, and both pushes the resultant value onto the stack and sets this as the key. If you dont catch the second way of changing the XOR key, it will quickly crash after the first call.
- the rest of the VM acts like a regular stack based machine, mathematical operations will merge the top two values, and there are patterns of IF statements for checking certain settings
- The only other odd instruction out is `FLAG`, which will be covered later.
Now that we have an emulator, lets see what happens in the program. I could run it, but I instead have a breakdown of exactly how the bytecode works (excluding the section involving the flag :p)
```
# values pushed to the stack
0101 
0100 
0101 
0101 
0101 
0101 
0101 
0101

f0 20 40 00 #checks if charging
f1 20 40 00 #checks if in airplane mode
f2 20 40 00 #checks if connected to internet
f0 20 40 00 #checks if not charging
01 2a #loads xorkey
f3 #starts encryption with key of 2a
2b 60
2b 1d
1b #xor, changes key to 0x7d
...
7a 53
7a 11
4a #xor, changes key to 0x42
43 59 
43 0d 
73 #xor, changes key to 0x54
55 bd
55 f5
65 #xor, changes key to 0x48
bc #decrypts stream
ff #prints flag
00 #ends
```

If you follow along with the emulator, you will soon find out, that the XOR values/keys are actually characters from the flag, reversed! The last instruction, `FLAG` will just append all of the characters together, and print the flag. I am not sure where it is displayed, but I believe it should be a popup that triggers on the app itself.

[https://www.hackthebox.com/achievement/challenge/158887/513]