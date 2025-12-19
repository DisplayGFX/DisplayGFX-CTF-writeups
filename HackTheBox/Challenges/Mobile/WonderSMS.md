WonderSMS
===

HTB Challenge

Credits to @i8br (X41) for the assist on decompiling

We only have one file. `WonderSMS.apk`

## Initial Enumeration

Looking inside the program, we can find the main package `com.rloura.wondersms`. All of the code in the APK is Java, so it would be good to get acquainted with the language.

From here, after browsing, we can see a few things of note. First, in `MainActivity`

```java
    static {
        System.loadLibrary("audio");
    }
```

This tells us that its loading a binary that is titled `audio`. I will come back to that shortly.

Also, if we browse more, we can see the following function prototype with the keyword `native`

```java
private final native ProcessedMessage processMessage(SmsMessage smsMessage);
```

Native should mean that the libraries set should already have the function. [Source](https://www.baeldung.com/java-native) In this case, `ProcesssedMessage`. This almost certainly means reversing `audo` library. If we look in the `resources` folder, and look in `lib`, there we can find the file `libaudio.so`. This must be our library.

Lets grab that, and start to analyze.

## `libaudio.so`

If you take a look at the `lib` folder, there are actually 4 versions of this binary shared object. 2 in ARM and 2 in x86, segmented further by being 32 bit or 64 bit. So feel free to grab whichever one you are more comfortable with. I chose to use x86_64.

On first load with Ghidra, let the program analyze the binary. 

The first thing that stands out is the functions. There are a bunch of `operator` functions, which all are either named `operator.delete` or `operator.new`. Also, there are a bunch of functions that begin with \_ These all seem like hints towards the binary being compiled from C++. 

![[wonderSMS_1.png]]

But, setting those aside, there are two functions worth considering. `JNI_OnLoad`, and the `processMessage` function. Lets take a look at the more immediate function, the `processMessage` function

## Java_com_rloura_wondersms_SmsReciever_processMessage

Looking at this code, it seems like a real mess! Why is this? Well, if you remember, this codebase uses Java. Java is not a compiled language, but instead it is interpreted. This means that it runs on a Virtual Machine. So it will use its own objects, with their own offsets. So to interpret the binary correctly, we need to bring our own header files in for Ghidra to interpret the binary correctly.

[ghidra-jni](https://github.com/extremecoders-re/ghidra-jni) is a repository that has exact instructions on how to load the data types into ghidra. Follow the instructions within this repository.

Once done, all that is left is to define the function signature, or the objects that come into the program. `JNIEnv_ *` for the first parameter should be enough.
```C
undefined8
Java_com_rloura_wondersms_SmsReceiver_processMessage
          (JNIEnv_ *param_1,undefined8 param_2,jmethodID param_3,undefined8 param_4,
          undefined8 param_5,undefined param_6)

{
  undefined uVar1;
  int iVar2;
  jclass p_Var3;
  jmethodID p_Var4;
  jstring str;
  char *__s;
  size_t sVar5;
  char *pcVar6;
  undefined8 uVar7;
  undefined uVar8;
  JNINativeInterface_ *pJVar9;
  undefined in_stack_ffffffffffffffc8;
  
  p_Var3 = (*param_1->functions->GetObjectClass)(&param_1->functions,(jobject)param_3);
  pJVar9 = param_1->functions;
  uVar1 = 0x16;
  p_Var4 = (*pJVar9->GetMethodID)
                     (&param_1->functions,p_Var3,"getMessageBody","()Ljava/lang/String;");
  uVar7 = 0;
  uVar8 = SUB81(pJVar9,0);
  str = (jstring)_JNIEnv::CallObjectMethod
                           (param_1,(_jmethodID *)param_3,(char)p_Var4,uVar1,uVar8,param_6,
                            in_stack_ffffffffffffffc8);
  __s = (*param_1->functions->GetStringUTFChars)(&param_1->functions,str,(jboolean *)0x0);
  sVar5 = strlen(__s);
  if (3 < (int)sVar5) {
    pcVar6 = (char *)calloc(4,1);
    strncpy(pcVar6,__s,4);
    iVar2 = atoi(pcVar6);
    free(pcVar6);
    if ((int)sVar5 < iVar2 + 4) {
      uVar7 = 0;
    }
    else {
      pcVar6 = (char *)calloc((long)iVar2,1);
      strncpy(pcVar6,__s + 4,(long)iVar2);
      p_Var3 = (*param_1->functions->FindClass)
                         (&param_1->functions,"com/rloura/wondersms/MessageSound");
      p_Var4 = (*param_1->functions->GetMethodID)(&param_1->functions,p_Var3,"<init>","([B)V");
      uVar1 = _JNIEnv::NewObject((_jclass *)param_1,(_jmethodID *)p_Var3,(char)p_Var4,(char)pcVar6,
                                 uVar8,param_6,in_stack_ffffffffffffffc8);
      p_Var3 = (*param_1->functions->FindClass)
                         (&param_1->functions,"com/rloura/wondersms/ProcessedMessage");
      p_Var4 = (*param_1->functions->GetMethodID)
                         (&param_1->functions,p_Var3,"<init>",
                          "(Lcom/rloura/wondersms/MessageType;Ljava/lang/String;Ljava/lang/String;Lc om/rloura/wondersms/MessageSound;)V"
                         );
      uVar7 = _JNIEnv::NewObject((_jclass *)param_1,(_jmethodID *)p_Var3,(char)p_Var4,2,0x21,0x21,
                                 uVar1);
    }
  }
  return uVar7;

```

Hmm, this function seems benign, so I will go over it quickly.

The first few function calls all are about obtaining the method of `getMessageBody`, and getting the string from it by calling the function. If the string is longer than 3 bytes, it will proceed into the conditional section of code, and do some math magic that is not relevant. Anyways, in the last section of code, it seems to prepare a java object to return with an object called `MessageSound` inside the `ProcessedMessage` object.

All of the functions called are suspiciously clean. No real issues to find. Hmm. What about the other identified function?

## JNI_OnLoad

JNI stands for Java Native Interface. If you ever have reversed binaries that mess with Java at all, you know this is what allows java to be executed by the binary. 

In this case `JNI_OnLoad` will always be called by the VM whenever a native library is loaded. [Source](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/invocation.html#JNJI_OnLoad) So, in this case, this code will be executed before anything else within the binary. Lets take a look at what this one contains.

```c
  p_Var1 = (*param_1->functions->FindClass)(&param_1->functions,(char *)&jni_local);
  iVar3 = -1;
  if ((int)p_Var1 == 0) {
    p_Var1 = (*jni_local->functions->FindClass)
                       (&jni_local->functions,"com/rloura/wondersms/SmsReceiver");
    if (p_Var1 != (jclass)0x0) {
      jVar2 = (*jni_local->functions->RegisterNatives)
                        (&jni_local->functions,p_Var1,&JNINativeMethod_001ec9f0,1);
      iVar3 = 0x10006;
      if ((int)jVar2 != 0) {
        iVar3 = (int)jVar2;
      }
    }
  }
```

To my imperfect understanding, this will load a local copy of `JNIEnv` into `jni_local`, and then find the `SmsReciever` class, and use the function `RegisterNatives`.  According to [the java docs on this function](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#RegisterNatives) this will register a native method, and the structure being pointed to has a function pointer. In this program, the native function is pointing to a static area in the library.

But, if we follow the function, it points to a different function than we just analyzed!

## `processor::processMessage`

Well well, the first function we analyzed was a red herring! Like the last time, set the first parameter to `JNIEnv_ *`

Lets analyze the function part by part.
```c
  p_Var4 = (*param_1->functions->GetObjectClass)(&param_1->functions,(jobject)param_3);
  uVar7 = 0x16;
  p_Var5 = (*param_1->functions->GetMethodID)
                     (&param_1->functions,p_Var4,"getMessageBody","()Ljava/lang/String;");
  lVar8 = 0;
  obj = (jobject)_JNIEnv::CallObjectMethod
                           ((_jobject *)param_1,(_jmethodID *)param_3,(char)p_Var5,uVar7,in_R8B,
                            in_R9B,in_stack_ffffffffffffff48);
  p_Var4 = (*param_1->functions->GetObjectClass)(&param_1->functions,obj);
  pJVar9 = param_1->functions;
  uVar7 = 0x16;
  p_Var5 = (*pJVar9->GetMethodID)(&param_1->functions,p_Var4,"toLowerCase","()Ljava/lang/String;");
  str = (jstring)_JNIEnv::CallObjectMethod
                           ((_jobject *)param_1,(_jmethodID *)obj,(char)p_Var5,uVar7,(char)pJVar9,
                            in_R9B,in_stack_ffffffffffffff48);
  chars = (*param_1->functions->GetStringUTFChars)(&param_1->functions,str,(jboolean *)0x0);
```

So, like last time, `getMessageBody` is called, and then the resultant string is set to lowercase and converted to UTF-8.

```c
do {
	pcVar1 = chars + lVar8;
	lVar8 = lVar8 + 1;
} while (*pcVar1 != '\0');
lVar6 = 1;
do {
	bVar2 = chars[lVar6 + -1];
	if (('z' < bVar2) || (bVar2 != 0x20 && (char)bVar2 < 'a')) {
	LAB_0017aab2:
	  __android_log_print(4,"Audio","Invalid encoding character");
	  goto LAB_0017aacc;
	}
	bVar2 = chars[lVar6];
	if (('z' < bVar2) || (bVar2 != 0x20 && (char)bVar2 < 'a')) goto LAB_0017aab2;
	lVar6 = lVar6 + 2;
} while (lVar6 != 0x1d);
```

This first loop will count how many characters there are in the freshly made string and store it in lvar8.

And then the next loop will go through each odd character (even though what the literal code says is different, this is probably a logical error on the creator's part), and check for them being a lowercase letter. It will continue to do this until it reaches 0x1d, or 29 characters.

```c
  if (0x24 < lVar8) {
    pVar10 = (processor)0x0;
                    /* try { // try from 0017aa4c to 0017aa56 has its CatchHandler @ 0017ab69 */
    f315732804((processor *)&stack0xffffffffffffff48,chars);
    if (((byte)pVar10 & 1) != 0) {
      operator.delete(local_a8);
    }
  }
```

So, if you compare the decompiled C code to the assembly, you will see a lot of missing code. we will come back to this soon. But, for now, it feeds the string, and some area in memory into the `f315732804`. 

## Processor

Before diving deeper, defining what this `processor` object is might help. Its worth noting that we did already analyze a function within the processor object.

A way to find this is by looking in the symbol tree in Ghidra.

![[wonderSMS_2.png]]

Looking inside this class, you will see an explosion of functions named similarly to the one we identified above, `f` and a string of numbers. Ignoring those, lets look at the other functions. In particular, `~processor`. [According to cppreference](https://en.cppreference.com/w/cpp/language/destructor)  this is a class destructor. So we can use this to learn about class and how its constructed.

```c
void __thiscall processor::~processor(processor *this)

{
  processor pVar1;
  
  if (((byte)this[0x78] & 1) == 0) {
    pVar1 = this[0x60];
  }
  else {
    operator.delete(*(void **)(this + 0x88));
    pVar1 = this[0x60];
  }
  if (((byte)pVar1 & 1) == 0) {
    pVar1 = this[0x48];
  }
  else {
    operator.delete(*(void **)(this + 0x70));
    pVar1 = this[0x48];
  }
  if (((byte)pVar1 & 1) == 0) {
    pVar1 = this[0x30];
  }
  else {
    operator.delete(*(void **)(this + 0x58));
    pVar1 = this[0x30];
  }
  if (((byte)pVar1 & 1) == 0) {
    pVar1 = this[0x18];
  }
  else {
    operator.delete(*(void **)(this + 0x40));
    pVar1 = this[0x18];
  }
  if (((byte)pVar1 & 1) == 0) {
    pVar1 = *this;
  }
  else {
    operator.delete(*(void **)(this + 0x28));
    pVar1 = *this;
  }
  if (((byte)pVar1 & 1) != 0) {
    operator.delete(*(void **)(this + 0x10));
    return;
  }
  return;
}
```

It seems like the construction of the object is a series of 6 pointers, with space inbetween for something to be put there. if you right click `processor` in ghidra and click `Edit Data Type`, you can change the object to reflect this. Set the offsets in the code to all be pointers. You can add enough space by editing `Size:` to be `0x90` long.

If you do this, you may notice that in the data type, there is 16 bytes inbetween each pointer. For now, set those spaces to be a char array of length 16, `char[16]`. a `char` is always 1 byte long, so its a good placeholder for any unknown bytes.

Now that we have the type for this object, lets revisit `processMessage`. 

So, in order to get Ghidra to properly add the type to the decompiled code, we need to edit the stack. go to the assembly view in the function, go to the top of the function. Right click -> `Function` -> `Analyze Stack`. 

![[wonderSMS_3.png]]


Then, if you look at the literal assembly code, you can see the byte writing starts at `local_b8` and ends at `local_3a`. So in the stack editor, you need to free up all of the data between those two hex addresses. You can do this by selecting a given item, and hitting `C` to clear the information at that location. Once this is done, at `-0xb8`, just change the datatype to `processor`. Once you do all of this, you can see an immediate change in the decompiled code.

```c
if (0x24 < lVar8) {
	local_b8.field0_0x0[0] = '\n';
	local_b8.field0_0x0[1] = 'U';
	local_b8.field0_0x0[2] = '\'';
	local_b8.field0_0x0[3] = 'f';
	local_b8.field0_0x0[4] = 'i';
	local_b8.field0_0x0[5] = ',';
	local_b8.field0_0x0[6] = '\0';
	local_b8.field2_0x18[0] = '\n';
	local_b8.field2_0x18[1] = 'T';
	local_b8.field2_0x18[2] = '&';
	local_b8.field2_0x18[3] = 'e';
	local_b8.field2_0x18[4] = 'h';
	local_b8.field2_0x18[5] = ',';
	local_b8.field2_0x18[6] = '\0';
	local_b8.field4_0x30[0] = '\n';
	local_b8.field4_0x30[1] = 'S';
	local_b8.field4_0x30[2] = '%';
	local_b8.field4_0x30[3] = 'f';
	local_b8.field4_0x30[4] = '^';
	local_b8.field4_0x30[5] = '^';
	local_b8.field4_0x30[6] = '\0';
	local_b8.field6_0x48[0] = '\n';
	local_b8.field6_0x48[1] = 'R';
	local_b8.field6_0x48[2] = '$';
	local_b8.field6_0x48[3] = 'm';
	local_b8.field6_0x48[4] = 'W';
	local_b8.field6_0x48[5] = 'l';
	local_b8.field6_0x48[6] = '\0';
	local_b8.field8_0x60[0] = '\f';
	local_b8.field8_0x60[1] = 'Q';
	local_b8.field8_0x60[2] = '#';
	local_b8.field8_0x60[3] = 'b';
	local_b8.field8_0x60[4] = '^';
	local_b8.field8_0x60[5] = 'Y';
	local_b8.field8_0x60[6] = '^';
	local_b8.field8_0x60[7] = '\0';
	local_b8.field10_0x78[0] = '\n';
	local_b8.field10_0x78[5] = 'q';
	local_b8.field10_0x78[1] = 'P';
	local_b8.field10_0x78[2] = 'X';
	local_b8.field10_0x78[3] = 'o';
	local_b8.field10_0x78[4] = '*';
	local_b8.field10_0x78[6] = '\0';
					/* try { // try from 0017aa4c to 0017aa56 has its CatchHandler @ 0017ab69 */
	f315732804(&local_b8,chars);
	if ((local_b8.field10_0x78[0] & 1U) != 0) {
	  operator.delete(local_b8.field11_0x88);
	}
	if ((local_b8.field8_0x60[0] & 1U) != 0) {
	  operator.delete(local_b8.field9_0x70);
	}
	if ((local_b8.field6_0x48[0] & 1U) != 0) {
	  operator.delete(local_b8.field7_0x58);
	}
	if ((local_b8.field4_0x30[0] & 1U) != 0) {
	  operator.delete(local_b8.field5_0x40);
	}
	if ((local_b8.field2_0x18[0] & 1U) != 0) {
	  operator.delete(local_b8.field3_0x28);
	}
	if ((local_b8.field0_0x0[0] & 1U) != 0) {
	  operator.delete(local_b8.field1_0x10);
	}
}
```

So, it seems like there was strings assigned. though they are all nonsense. I am sure this will come in handy later. Now onto the `f` functions.

## Obfuscation, `f` functions abound!

Here is what `f315732804` looks like on the inside.
```c
undefined8 __thiscall processor::f315732804(processor *this,char *param_1)

{
  int iVar1;
  undefined8 uVar2;
  
  iVar1 = (int)param_1[0x11] * (int)param_1[0xb] +
          ((int)param_1[0x1b] * (int)param_1[1] - (int)param_1[5] * (int)param_1[3]);
  if (iVar1 == -0xbb35) {
    uVar2 = f55246438(this,param_1);
    return uVar2;
  }
  if (iVar1 == -0x3f30) {
    iVar1 = (int)param_1[0xf] * (int)param_1[7] +
            (int)param_1[9] * (int)param_1[0x15] + (int)param_1[0xd] * (int)param_1[0x17];
    if (iVar1 == -0xacb4) {
      uVar2 = f2376589827(this,param_1);
      return uVar2;
    }
    if (iVar1 == 0xbc3f) {
      uVar2 = f677797901(this,param_1);
      return uVar2;
    }
  }
  else if (iVar1 == 0x38f7) {
    iVar1 = (int)param_1[0xf] * (int)param_1[7] +
            (int)param_1[9] * (int)param_1[0x15] + (int)param_1[0xd] * (int)param_1[0x17];
    if (iVar1 == -0x6e9b) {
      uVar2 = f512680851(this,param_1);
      return uVar2;
    }
    if (iVar1 == 0x70de) {
      uVar2 = f3471812644(this,param_1);
      return uVar2;
    }
    if (iVar1 == 0x876a) {
      uVar2 = f1100030004(this,param_1);
      return uVar2;
    }
  }
  __android_log_print(4,"Audio","Error decoding audio");
  return 0xffffffff;
}
```

My oh my, its a bunch of branching paths. But whats similar with all of the paths is that it compares all of the odd characters, one by one, in the string given into this function. each path will continue down the path. Lets continue down the first path as an example, but know that many paths have different variables, but look similar.
```c
undefined8 __thiscall processor::f55246438(processor *this,char *param_1)

{
  int iVar1;
  undefined8 uVar2;
  
  iVar1 = (int)param_1[0xf] * (int)param_1[7] +
          (int)param_1[9] * (int)param_1[0x15] + (int)param_1[0xd] * (int)param_1[0x17];
  if (iVar1 < 0xa2f5) {
    if (iVar1 == 0x16d0) {
      uVar2 = f3982753770(this,param_1);
      return uVar2;
    }
    if (iVar1 == 0x1a17) {
      uVar2 = f3710132390(this,param_1);
      return uVar2;
    }
  }
  else {
    if (iVar1 == 0xa2f5) {
      uVar2 = f4067919320(this,param_1);
      return uVar2;
    }
    if (iVar1 == 0xba44) {
      uVar2 = f3743893872(this,param_1);
      return uVar2;
    }
  }
  __android_log_print(4,"Audio","Error decoding audio");
  return 0xffffffff;
}

undefined8 __thiscall processor::f3982753770(processor *this,char *param_1)

{
  undefined8 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = (int)param_1[0x17];
  iVar4 = (int)param_1[0x1b];
  iVar2 = param_1[7] * iVar3 - (param_1[0xf] * iVar4 + (int)param_1[1] * (int)param_1[0xd]);
  if (iVar2 == -0x5bf4) {
    if (param_1[0x19] * iVar3 + param_1[9] * iVar4 == 0x6041) {
      uVar1 = check_extension(this,param_1);
      return uVar1;
    }
  }
  else if (iVar2 == -0x5405) {
    iVar2 = param_1[0x19] * iVar3 + param_1[9] * iVar4;
    if (((iVar2 == -0x4c8f) || (iVar2 == 0x55f9)) || (iVar2 == 0x5597)) {
      uVar1 = check_extension(this,param_1);
      return uVar1;
    }
  }
  else if (iVar2 == 0x1598) {
    iVar2 = param_1[0x19] * iVar3 + param_1[9] * iVar4;
    if ((iVar2 == 0x79f2) || (iVar2 == 0x6a7d)) {
      uVar1 = check_extension(this,param_1);
      return uVar1;
    }
  }
  __android_log_print(4,"Audio","Error decoding audio");
  return 0xffffffff;
}
```

So, clearly, we want to avoid the "Error decoding audio" and reach the function called `check_extension`. in all of the paths, you may notice that every single odd character is checked at least twice. There has to be at least one path that is valid, else this program would never work. 

If you are also a careful observer, you will notice that some paths are invalid. for instance, adding 4 characters together will never result in a negative number, but some of the if statements check for this. Meaning, there's a mathematical relation between all of the odd characters in `param_1`, and thus a way to figure out how to solve that set of relationships to produce one set of characters.

# Satisfiability solver (SAT solver) and z3

Satisfiability is a theory in concept in Computer Science and Mathematics where you have a series of formulas and variables, and if you can find a set of variables that satisfy all of the formulas to be true, then the set of formulas are satisfiable. A SAT solver will similarly try to find a set of variables and formulas where the input will result in the formulas all being satisfied, even if the formulas are in fact part of computer programs.

If you think about each of the `f` functions listed above as a set of formulas, this is where a SAT solver can come in handy. z3 is such a solver, and has an API in python that is easy to use.

I renamed all of the functions as `used1` and so on, in order of what was encountered. so, if you turn each of the functions into a satisfiability problem, and task z3 to solve it, it will return back if it can be solved, and what will get you to a `check_extension` function call.

So, first, lets establish variables so that any formula is constrained correctly.

```python
from z3 import *

# constraint for odd characters, according to checks in program
custom_range = list(range(0x61, 0x7a)) + [0x20]

# instantiate new solver
s2 = Solver()
```

Then, lets create variables for each and every byte that will be pulled from the string. From above, we know that the string will be at least 0x24 bytes long. And if we add in all of the constraints we discovered earlier, this is what the code looks like.

```python
#for each byte in input string, create a variable
for i in range(0x28):
    #create variable name for each byte
    var_name = f'b_0x{i:x}'
    # BitVector will be a way to efficiently emulate each byte.
    # If each variable is not given more than 8 bits, any math operations will overflow the BitVec, and not be emulated properly. i.e. 1000 0000 + 1000 0010 = 0000 0011 instead of 1 0000 0010
    globals()[var_name] = BitVec(var_name, 16)
    # Creates variables in python environment. Instead of large block of declaration, this is done instead
    s2.add(globals()[var_name] >= 0,globals()[var_name] <= 127)
    #constraining every odd character
    if i%2 == 1:
        s2.add(Or(globals()[var_name] == 0x20,globals()[var_name]>=0x61))
```

Then, one function at a time, we check the satisfiability of a given function. With the `And` functions acting as branches on the path, and `Or` acting as the split points of each branch.
```python

used10 = Or(
    And(b_0xf * b_0x7 + b_0x9 * b_0x15 + b_0xd * b_0x17 ==-0x5957,
        Or(
            b_0x19 * b_0x17 + b_0x9 * b_0x1b ==0x2429,
            b_0x19 * b_0x17 + b_0x9 * b_0x1b ==0x5485,
            b_0x19 * b_0x17 + b_0x9 * b_0x1b ==0x514a,
        )
    ),
    And(b_0xf * b_0x7 + b_0x9 * b_0x15 + b_0xd * b_0x17 == 0x5723,
            b_0x19 * b_0x17 + b_0x9 * b_0x1b ==0xa0e,
    ),
)



s2.add(used10)
print(s2.check())
```

for instance, right now this prints out `sat`.

However, it seems like this is not enough to find one solution. too many of the functions are satisfiable, but its unlikely that all branches are satisfiable. So lets keep on looking ahead. at `check_extension`.

## A Peak at `check_extension`.

We can see, no matter what the characters are in the string, there are additional checks to the string `param_1`.

```c
  if ((param_1[4] == ' ') &&
     (param_1_0x9 = param_1[9],
     (int)param_1[0x17] * (int)param_1[0x19] + (int)param_1[0x1d] * (int)param_1_0x9 == 0x1940)) {
    param_1_0x1 = param_1[1];
    param_1_0x11 = param_1[0x11];
    if (((int)param_1_0x1 + (int)(char)param_1_0x11) - (int)param_1[7] != 0x6a) goto LAB_0017445d;
    param_1_0xd = param_1[0xd];
    param_1_0x5 = param_1[5];
    if ((((int)(char)param_1_0xd - (int)param_1[7]) + (int)param_1_0x5 != 0x50) ||
       (param_1_0xb = param_1[0xb],
       ((int)(char)param_1_0xd - (int)param_1_0x1) + (int)(char)param_1_0xb != 0x68))
    goto LAB_0017445d;
```

To clean up the logic, it implements the 4 following formulas
```
b_0x17 * b_0x19 + b_0x1d * b_0x9 == 0x1940
b_0x1 + b_0x11 - b_0x7 == 0x6a
b_0xd - b_0x7 + b_0x5 == 0x50
b_0xd - b_0x1 + b_0xb == 0x68
```

These can go right back into the z3 solver.

## Sat solving the obfuscation

returning back to the python script in process, lets add the following checks.
```python
checkextension = And(
b_0x1 + b_0x11 - b_0x7 == 0x6a,
b_0xd - b_0x7 + b_0x5 == 0x50,
b_0xd - b_0x1 + b_0xb == 0x68,
b_0x17 * b_0x19 + b_0x1d * b_0x9 == 0x1940,
)
s2.add(checkextension)
```
Then, if we go back to one of the `used` functions, we can now see that it will return `unsat`. meaning that no combination of bytes can pass through this function.

Eventually, you will be able to find one path through all of the branching paths.
```python
used15 = Or([b_0x17 * b_0x19 + b_0x1b * b_0x9 == X for X in [0x3236,0x39ff]])

used6 = And(b_0x7 * b_0x17 - (b_0xf * b_0x1b + b_0x1 * b_0xd) == -0x3145,
            used15)

used0 = Or(
    And(
        b_0x11 * b_0xb + (b_0x1b * b_0x1 - b_0x5 * b_0x3) == 0x38f7,
        And(
            b_0xf * b_0x7 + b_0x9 * b_0x15 + b_0xd * b_0x17 == 0x876a,
            used6
        )
    )
)

s2.add(used0)
s2.add(checkextension)
print(s2.check())

$ python3 sat.py
sat
```

then, we can print out exactly which characters will pass this check.

```python
if s2.check() == sat:
    model = s2.model()
    print("Solution found:")
    print("model[b_0x1] = ", chr(model[b_0x1].as_long()))
    print("model[b_0x3] = ", chr(model[b_0x3].as_long()))
    print("model[b_0x5] = ", chr(model[b_0x5].as_long()))
    print("model[b_0x7] = ", chr(model[b_0x7].as_long()))
    print("model[b_0x9] = ", chr(model[b_0x9].as_long()))
    print("model[b_0xb] = ", chr(model[b_0xb].as_long()))
    print("model[b_0xd] = ", chr(model[b_0xd].as_long()))
    print("model[b_0xf] = ", chr(model[b_0xf].as_long()))
    print("model[b_0x11] = ", chr(model[b_0x11].as_long()))
    print("model[b_0x13] = ", chr(model[b_0x13].as_long()))
    print("model[b_0x15] = ", chr(model[b_0x15].as_long()))
    print("model[b_0x17] = ", chr(model[b_0x17].as_long()))
    print("model[b_0x19] = ", chr(model[b_0x19].as_long()))
    print("model[b_0x1b] = ", chr(model[b_0x1b].as_long()))
```

No matter how many times `check()` is called, none of the model values will change. This is a sign we have only one solution.  Lets look at what is printed out.
```
Solution found:
model[b_0x1] =  o
model[b_0x3] =  r
model[b_0x5] =  a
model[b_0x7] =  t
model[b_0x9] =  e
model[b_0xb] =  t
model[b_0xd] =  c
model[b_0xf] =  t
model[b_0x11] =  o
model[b_0x13] =   
model[b_0x15] =  o
model[b_0x17] =  e
model[b_0x19] =   
model[b_0x1b] =  s
```

Strange... Well, this is a good basis to proceed on. We now know at least half of the characters in the input string. And we know that there's only one path taken for the function call.

## check_extension - revisited

So, we now know as much as we can from the `f` functions. Lets now look inside the `check_extension` function.

First is the character combination checking that we covered earlier. But worth specifying, there is one character that is specified that hasnt been covered.
```c
(param_1[4] == ' ')
```

it specifies that the 4th character is always going to be a space character. This can be added to the `checkextension` to further specify the string.

```python
checkextension = And(
	# known values
    b_0x4 == ord(' '),
b_0x1 + b_0x11 - b_0x7 == 0x6a,
b_0xd - b_0x7 + b_0x5 == 0x50,
b_0xd - b_0x1 + b_0xb == 0x68,
b_0x17 * b_0x19 + b_0x1d * b_0x9 == 0x1940,
)
```

Moving on, after these checks, there is one long string creation
```c
    __ptr = (byte *)calloc(0x28,1);
    param_1_0x8 = param_1[8];
    *__ptr = param_1_0x8;
    param_1_0x14 = param_1[0x14];
    __ptr[1] = param_1_0x14;
    __ptr[2] = param_1_0x14;
    __ptr[3] = param_1_0x1 + 1;
...
    __ptr[0x27] = param_1_0x0 + 4;
	this_00 = (byte **)operator.new(8);
    *this_00 = __ptr;
```

This seems to use the input string, but also the even characters from the input string. for now, lets fill in the long string with the ones we do know.
```python
    print("model[b_0x8] =","???")
    print("model[b_0x14] =","???")
    print("model[b_0x14] =","???")
    print("model[b_0x1]+1 =",chr(model[b_0x1].as_long()  + 1))
...
    print("model[b_0x11] =",chr(model[b_0x11].as_long() ))
    print("model[b_0x3] =",chr(model[b_0x3].as_long() ))
    print("model[b_0xa] =","???")
    print("model[b_0x0] + 4 =","???")
```

```
model[b_0x8] = ???
model[b_0x14] = ???
model[b_0x14] = ???
model[b_0x1]+1 = p
model[b_0x1c] = ???
model[b_0x1c] - 0xb = ???
model[b_0x1c] - 0xb = ???
model[b_0x8] XOR 0x20 = ???
model[b_0x14] XOR 0x20 = ???
model[b_0x5] + 1 XOR 0x20 = B
model[b_0x0] + 2 = ???
model[b_0x1a] XOR 0x20 = ???
model[b_0x5] - 2 = _
model[b_0x9] + 2 = g
model[b_0xa] XOR 0x5d = ???
model[b_0xb] = t
model[b_0x5] - 2 = _
model[b_0xe] = ???
model[b_0x12] = ???
model[b_0x16] - 4 = ???
model[b_0x3] = r
model[b_0x5] - 2 = _
model[b_0xa] XOR 0x5d = ???
model[b_0xe] = ???
model[b_0x1b] = s
model[b_0xa] XOR 0x5d    - 2 = ???
model[b_0x16] +1 = ???
model[b_0x0] XOR 0x20 = ???
model[b_0x5] - 2 = _
model[b_0xe] = ???
model[b_0xb] XOR 0x20 = T
model[b_0x5] - 2 = _
model[b_0x2] = ???
model[b_0xa] = ???
model[b_0x1a] = ???
model[b_0xd] = ???
model[b_0x11] = o
model[b_0x3] = r
model[b_0xa] = ???
model[b_0x0] + 4 = ???
```

Nothing quite yet, but I do see that all of the characters are still readable ascii.

Lets move onwards for now.

Afterwards, the given string is checked for length, and then another check is performed.

```c
iVar4 = (int)param_1[0x13] + ((int)param_1[0xf] - (int)param_1[0x11]);
iVar8 = 3;
	if (iVar4 < 0x25) {
  if (iVar4 == -0x18) {
	get_encoding((int)local_a8);
	goto LAB_00174221;
  }
  if (iVar4 == -0x13) {
	get_encoding((int)local_a8);
	goto LAB_00174221;
  }
  if (iVar4 == 0xf) {
	get_encoding((int)local_a8);
	goto LAB_00174221;
  }
}
else {
  if (iVar4 == 0x25) {
	get_encoding((int)local_a8);
  }
  else if (iVar4 == 0x30) {
	get_encoding((int)local_a8);
  }
  else {
	if (iVar4 != 0x147) goto LAB_00174425;
	get_encoding((int)local_a8);
  }
```

However, if you check the assembly, 2 other variables are loaded into the registers before `get_encoding` is called. so lets change the function signatures. `RDI` has a pointer moved to it. `RSI` also has a pointer moved, and `EDX`(RDX) has an integer moved into that value manually. So lets edit the function signature appropriately. Right Click -> `Edit Function Signature`, and add 2 variables of the appropriate type.

Here is one one branch looks like.

```c
      if (iVar4 == -0x18) {
        get_encoding(local_a8,this->field0_0x0,2);
        goto LAB_00174221;
      }
```

Much better! We can now set the type of the second parameter to be a `processor *` pointer.

Oh, and in case you are curious, `(int)param_1[0x13] + ((int)param_1[0xf] - (int)param_1[0x11])` equals `0x25` with the currently known input, so the `get_encoding` function is given `5` as an input.

Now seems like an appropriate time to analyze the function.
## get_encoding

```c
undefined * processor::get_encoding(undefined *param_1,processor *param_2,int param_3)

{
  *(undefined2 *)param_1 = 0;
                    /* try { // try from 0017a47d to 0017a486 has its CatchHandler @ 0017a52f */
  std::__ndk1::basic_string<>::basic_string
            (&local_40,(basic_string *)(param_2->field0_0x0 + (long)param_3 * 0x18));
  bVar4 = ((byte)local_40 & 1) == 0;
  if (bVar4) {
    if ((byte)local_40 >> 1 == 0) goto LAB_0017a4fe;
  }
  else if (local_38 == 0) goto LAB_0017a4fe;
  uVar3 = 0;
  do {
    puVar2 = local_3f;
    if (!bVar4) {
      puVar2 = local_30;
    }
                    /* try { // try from 0017a4e1 to 0017a4e8 has its CatchHandler @ 0017a53a */
    std::__ndk1::basic_string<>::push_back
              ((basic_string<> *)param_1,puVar2[uVar3] + (char)param_3 + '\a');
    uVar3 = uVar3 + 1;
    bVar4 = ((byte)local_40 & 1) == 0;
    uVar1 = local_38;
    if (bVar4) {
      uVar1 = (ulong)((byte)local_40 >> 1);
    }
  } while (uVar3 < uVar1);
LAB_0017a4fe:
  if (!bVar4) {
    operator.delete(local_30);
  }
  return param_1;
}
```

To make a long and complex function short, it will take the processor object, and search for an entry/pointer based on the array of the processor object. this is where the pointers were assumed to be.

Then, for each character in the string assigned waaaaay back at the beginning, it will add 7 to each character, and the index given into the program. Meaning, we can decrypt the weird string assignments at the beginning of our analysis.

Lets do just that to all of the strings we had in python.
```python
stringarray = [
    [0xa, ord('U'), ord("'"), ord('f'), ord('i'), ord(',')],
    [0xa, ord('T'), ord('&'), ord('e'), ord('h'), ord(',')],
    [0xa, ord('S'), ord('%'), ord('f'), ord('^'), ord('^')],
    [0xa, ord('R'), ord('$'), ord('m'), ord('W'), ord('l')],
    [ord('\f'), ord('Q'), ord('#'), ord('b'), ord('^'), ord('Y'), ord('^')],
    [0xa, ord('P'), ord('X'), ord('o'), ord('*'), ord('q')],
]

# Function to add (7 + position) to each byte and render as characters
def process_strings(stringarray):
    processed_strings = []
    for idx, string in enumerate(stringarray):
        processed_string = ""
        for byte in string:
            if byte == 0:
                break
            new_byte = (byte + 7 + idx) % 256  # Ensure the value stays within byte range
            processed_string += chr(new_byte)
        processed_strings.append(processed_string)
    return processed_strings

# Process the strings
processed_strings = process_strings(stringarray)
```

```
String 0: \.mp3
String 1: \.mp4
String 2: \.ogg
String 3: \.wav
String 4: \.midi
String 5: \d{6}
```
Hmm, thats very interesting. so, these are regex patterns. They will look at the end of the string for all of the patterns. Most of them look for file endings, but one looks for 6 digits at the end of a string. You can confirm this yourself by using a site like [regexr.com](https://regexr.com/) .

Combining this with what we know about the input, this means the binary will look for 6 digits in the string we give it.


## check_extension - Returning for the Finale

With the knowledge that the function creates a regex string, we can read through the rest of the function, and can spot similar functions like `basic_regex<>`, `__search<>`, and so on. Following that, we can see an interesting function call. (`result_string` is the result from the regex search)
```c
httpcon::post((httpcon *)this_00,(basic_string)result_string);
```

and inside the function, we can see its meant to emulate sending data to a real attacker.
```c
void __thiscall httpcon::post(httpcon *this,basic_string param_1)

{
  byte *pbVar1;
  undefined4 in_register_00000034;
  
  pbVar1 = (byte *)CONCAT44(in_register_00000034,param_1);
  if ((*pbVar1 & 1) == 0) {
    pbVar1 = pbVar1 + 1;
  }
  else {
    pbVar1 = *(byte **)(pbVar1 + 0x10);
  }
  __android_log_print(4,&DAT_001493ba,"Uploading %s via POST to %s...",pbVar1,*(undefined8 *)this);
  return;
}
```

So, we know that `httpcon`, or the first parameter is supposed to be a URL, and the second parameter will be the 6 digit number that the program was searching for. With this in mind, lets head back, and start making educated guesses.

## Clues by Inductive Logic - the Final URL

So, revisiting the large string that is enciphered, we know that the string produced is a URL that reaches out over HTTP. Every URL over HTTP will always start with `http://`. lets look at the string printed out in python.
```python
    print("model[b_0x8] =","???")
    print("model[b_0x14] =","???")
    print("model[b_0x14] =","???")
    print("model[b_0x1]+1 =",chr(model[b_0x1].as_long()  + 1))
    print("model[b_0x1c] =","???")
    print("model[b_0x1c] - 0xb =","???")
    print("model[b_0x1c] - 0xb =","???")
```

We know that the 4th character ultimately prints out `p`, so we can confirm the hunch that this is indeed a URL! if we assume that `0x8`, `0x14` and `0x1c` are equal to the corresponding characters of `h`, `t`, and `:`, we can try it out.
```python
checkextension = And(
    # known values
    b_0x4 == ord(' '),
    #edcational guesses
    b_0x8 == ord('h'),
    b_0x14 == ord('t'),
    b_0x1c == 58, # ascii for :
    
b_0x1 + b_0x11 - b_0x7 == 0x6a,
b_0xd - b_0x7 + b_0x5 == 0x50,
b_0xd - b_0x1 + b_0xb == 0x68,
b_0x17 * b_0x19 + b_0x1d * b_0x9 == 0x1940,
)
...
```

```
model[b_0x1] = o
model[b_0x3] = r
model[b_0x4] =  
model[b_0x5] = a
model[b_0x7] = t
model[b_0x8] = h
model[b_0x9] = e
model[b_0xb] = t
model[b_0xd] = c
model[b_0xf] = t
model[b_0x11] = o
model[b_0x13] =  
model[b_0x14] = t
model[b_0x15] = o
model[b_0x17] = e
model[b_0x19] =  
model[b_0x1b] = s
model[b_0x1c] = :


model[b_0x8] = h
model[b_0x14] = t
model[b_0x14] = t
model[b_0x1]+1 = p
model[b_0x1c] = :
model[b_0x1c] - 0xb = /
model[b_0x1c] - 0xb = /
model[b_0x8] XOR 0x20 = H
model[b_0x14] XOR 0x20 = T
model[b_0x5] + 1 XOR 0x20 = B
...
```

Not only did that work, it gave the first 3 letters of the flag!

Another guess we can make, now that both strings are starting to make sense, is that the next character after `http://HTB` is `{`. which means `0x0` should be `y`.
```
model[b_0x0] = y
model[b_0x1] = o
model[b_0x3] = r
model[b_0x4] =  
model[b_0x5] = a
model[b_0x7] = t
model[b_0x8] = h
model[b_0x9] = e
model[b_0xb] = t
model[b_0xd] = c
model[b_0xf] = t
model[b_0x11] = o
model[b_0x13] =  
model[b_0x14] = t
model[b_0x15] = o
model[b_0x17] = e
model[b_0x19] =  
model[b_0x1b] = s
model[b_0x1c] = :

model[b_0x8] = h
model[b_0x14] = t
model[b_0x14] = t
model[b_0x1]+1 = p
model[b_0x1c] = :
model[b_0x1c] - 0xb = /
model[b_0x1c] - 0xb = /
model[b_0x8] XOR 0x20 = H
model[b_0x14] XOR 0x20 = T
model[b_0x5] + 1 XOR 0x20 = B
model[b_0x0] + 2 = {
...
model[b_0x0] XOR 0x20 = Y
...
model[b_0x0] + 4 = }
```

That also is confirmed by the end of the flag suddenly popping up as well! Now, lets look at the input string
```
yo_r a_the_t_c_t_o_ to_e_ _s:
```
These look like words! lets make some more guesses. Most obvious is `u` for `your` and `i` for `is`.

```
your a_the_t_c_t_o_ to_e_ is:
http://HTB{I_g_t____r___s__Y__T___i_or_}
```

And, for the last step, if you remember the regex, you can make a guess to wat the last two words could be. `authentication token`

```
your authentication token is:

http://HTB{[snip]}
```

And that gets the flag!

https://www.hackthebox.com/achievement/challenge/158887/609