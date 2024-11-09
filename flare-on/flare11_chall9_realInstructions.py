import capstone
import struct
import re
stack = []

ASM_MAKE = False
if ASM_MAKE:
    print(".intel_syntax noprefix")

programOffset = 0x95ef0 #Painless. Hover over the desired instruction, look at the file offset
running_offset = 0
last_call_byte = 0x4B
with open("../serpentine.exe","rb") as x:
    fileBytes = bytearray(x.read()[programOffset:0x800000+programOffset])
assert fileBytes[0:2] == bytearray(b'\xf4\x46')

PRINT_UNWIND = True
PRINT_CONTEX = True

dispatchContext = -1

reg2num = {
        'RAX': 0,
        'rax': 0,
        'RCX': 1,
        'rcx': 1,
        'RDX': 2,
        'rdx': 2,
        'RBX': 3,
        'rbx': 3,
        'RSP': 4,
        'rsp': 4,
        'RBP': 5,
        'rbp': 5,
        'RSI': 6,
        'rsi': 6,
        'RDI': 7,
        'rdi': 7,
        'r8': 8,
        'r9': 9,
        'r10': 10,
        'r11': 11,
        'r12': 12,
        'r13': 13,
        'r14': 14,
        'r15': 15,
        'mxcsr':16
        }

num2reg ={
        0:'rax',
        1:'rcx',
        2:'rdx',
        3:'rbx',
        4:'rsp',
        5:'rbp',
        6:'rsi',
        7:'rdi',
        8:'r8',
        9:'r9',
        10:'r10',
        11:'r11',
        12:'r12',
        13:'r13',
        14:'r14',
        15:'r15',
        16:'mxcsr'
}

previousRegNum = None

regNumContains={
        0:  '',
        1:  '',
        2:  '',
        3:  '',
        4:  '',
        5:  '',
        6:  '',
        7:  '',
        8:  '',
        9:  '',
        10: '',
        11: '',
        12: '',
        13: '',
        14: '',
        15: '',
        16: '',
}

reg64to32={
    'rax':'eax',
    'rcx':'ecx',
    'rdx':'edx',
    'rbx':'ebx',
    'rsp':'esp',
    'rbp':'ebp',
    'rsi':'esi',
    'rdi':'edi',
    'r8':'r8d',
    'r9':'r9d',
    'r10':'r10d',
    'r11':'r11d',
    'r12':'r12d',
    'r13':'r13d',
    'r14':'r14d',
    'r15':'r15d',
    "MxCsr":"MxCsr" #taking care of you, later
}

contextOffset = {
0x0:"P1Home",
0x8:"P2Home",
0x10:"P3Home",
0x18:"P4Home",
0x20:"P5Home",
0x28:"P6Home",
0x30:"ContextFlags",
0x34:"MxCsr",
0x38:"SegCs",
0x3a:"SegDs",
0x3c:"SegEs",
0x3e:"SegFs",
0x40:"SegGs",
0x42:"SegSs",
0x44:"EFlags",
0x48:"Dr0",
0x50:"Dr1",
0x58:"Dr2",
0x60:"Dr3",
0x68:"Dr6",
0x70:"Dr7",
0x78:"rax",
0x80:"rcx",
0x88:"rdx",
0x90:"rbx",
0x98:"rsp",
0xa0:"rbp",
0xa8:"rsi",
0xb0:"rdi",
0xb8:"r8",
0xc0:"r9",
0xc8:"r10",
0xd0:"r11",
0xd8:"r12",
0xe0:"r13",
0xe8:"r14",
0xf0:"r15",
0xf8:"rip",
0x100:"u",
0x300:"VectorRegister",
0x4a0:"VectorControl",
0x4a8:"DebugControl",
0x4b0:"LastBranchToRip",
0x4b8:"LastBranchFromRip",
0x4c0:"LastExceptionToRip",
0x4c8:"LastExceptionFromRip",
}

def funcIntercept(fun:capstone.CsInsn):
    global regNumContains
    reg_pull_pat = r'\s*,\s*\wword ptr\s*\[(\w*)\s*\+\s*0x[0-9a-fA-F]+\]'# to 
    match = re.search(reg_pull_pat, fun.op_str)
    
    # if not ASM_MAKE and (
    #     ("mov" in fun.mnemonic and not fun.mnemonic == 'movzx' and not ', 0x' in fun.op_str and not 'qword ptr [r9 + 0x28]' in fun.op_str)
    #     or ('ldmxcsr' in fun.mnemonic)
        
    # ):
    #     return
    if "qword ptr [r9 + 0x28]" in fun.op_str and regNumContains[reg2num['r9']] == 'DISPATCHER_CONTEXT':
        if not ASM_MAKE:
            if PRINT_CONTEX:
                print("0x{:6x}:".format(fun.address),"\t",end='')
                print("ContextRecord to",fun.op_str[:4].strip(" ").strip(","))
        regNumContains[reg2num[fun.op_str[:4].strip(" ").strip(",")]] = 'ContextRecord'
    elif "ldmxcsr" in fun.mnemonic:
        reg_pull_pat = r'\s*\wword ptr\s*\[(\w*)\s*\+\s*0x[0-9a-fA-F]+\]'
        match = re.search(reg_pull_pat, fun.op_str)
        if "word ptr ["  in fun.op_str and match and regNumContains[reg2num[match.group(1)]] == 'ContextRecord':
            if ASM_MAKE:
                offset_pattern = r'\s*\wword ptr\s*\[\w*\s*\+\s*(0x[0-9a-fA-F]+)\]'
                match = re.search(offset_pattern,fun.op_str)
                if contextOffset[int(match.group(1),16)] == "MxCsr":
                    pass
                else:
                    print("movd xmm0, ",end='')
                    if int(match.group(1),16) > 0x100 and int(match.group(1),16) < 0x300:
                        print("some weird value from XMM regs",end='')
                    elif int(match.group(1),16) > 0x200:
                        print("Vector Registers? cmon",end='')
                    else:
                        print(reg64to32[contextOffset[int(match.group(1),16)]],end='')
                    print("#ld-mxcsr from contextObj")
            else:
                try:
                    print("0x{:6x}:".format(fun.address),"\t",end='')
                    print("moving previous",end=' ')
                    offset_pattern = r'\s*\wword ptr\s*\[\w*\s*\+\s*(0x[0-9a-fA-F]+)\]'
                    match = re.search(offset_pattern,fun.op_str)
                    if int(match.group(1),16) > 0x100 and int(match.group(1),16) < 0x300:
                        print("some weird value from XMM regs",end=' ')
                    elif int(match.group(1),16) > 0x200:
                        print("Vector Registers? cmon",end=' ')
                    else:
                        print(contextOffset[int(match.group(1),16)],end=' ')
                    print("into mxcsr")
                except:
                    print("0x{:6x}:".format(fun.address),"\t",end='')   
                    print("{} {}".format(fun.mnemonic, fun.op_str))
                    raise NotImplementedError
        else:
            raise NotImplementedError
    elif fun.mnemonic == 'mov' and "word ptr [" in fun.op_str[4:] and match and regNumContains[reg2num[match.group(1)]] == 'ContextRecord' :
        if ASM_MAKE:
            print("mov ",end='')
            print(fun.op_str[:4].strip(" ").strip(","),", ", end='',sep='')
            offset_pattern = r',\s*\wword ptr\s*\[\w*\s*\+\s*(0x[0-9a-fA-F]+)\]'
            match = re.search(offset_pattern,fun.op_str)
            if int(match.group(1),16) > 0x100 and int(match.group(1),16) < 0x300:
                print("some weird value from XMM regs",end='')
            elif int(match.group(1),16) > 0x200:
                print("Vector Registers? cmon",end='')
            else:
                print(contextOffset[int(match.group(1),16)],end='')
            print("#mov from contextObj")
            
        else:
            print("0x{:6x}:".format(fun.address),"\t",end='')
            print("moving previous",end=' ')
            offset_pattern = r',\s*\wword ptr\s*\[\w*\s*\+\s*(0x[0-9a-fA-F]+)\]'
            match = re.search(offset_pattern,fun.op_str)
            if int(match.group(1),16) > 0x100 and int(match.group(1),16) < 0x300:
                print("some weird value from XMM regs",end=' ')
            elif int(match.group(1),16) > 0x200:
                print("Vector Registers? cmon",end=' ')
            else:
                print(contextOffset[int(match.group(1),16)],end=' ')
            print("into",fun.op_str[:4].strip(" ").strip(","))

            newreg = fun.op_str[:4].strip(" ").strip(",").strip("d")

            if 'e' in newreg:
                newreg = newreg.replace("e","r")

            regNumContains[reg2num[newreg]] = ''

    elif (fun.mnemonic == 'sub' or fun.mnemonic == "xor" or fun.mnemonic == "add") and "word ptr [" in fun.op_str[4:] and match and regNumContains[reg2num[match.group(1)]] == 'ContextRecord' :
        if ASM_MAKE:
            pass
        else:
            print("0x{:6x}:".format(fun.address),"\t",end='')
            print(fun.mnemonic,sep='',end=' ')
            reg = fun.op_str[:4].strip(" ").strip(",")
                
            print(reg,end='')
            print(", previous",end=' ')
            offset_pattern = r',\s*\wword ptr\s*\[\w*\s*\+\s*(0x[0-9a-fA-F]+)\]'
            match = re.search(offset_pattern,fun.op_str)
            if int(match.group(1),16) > 0x100 and int(match.group(1),16) < 0x300:
                print("some weird value from XMM regs",end=' ')
            elif int(match.group(1),16) > 0x200:
                print("Vector Registers? cmon",end=' ')
            else:
                print(contextOffset[int(match.group(1),16)])



    else:
        if not ASM_MAKE:
            print("0x{:6x}:".format(fun.address),"\t",end='')   
        print("{} {}".format(fun.mnemonic, fun.op_str))


def funcBreakdown(loc,funcStr):
    global last_call_byte
    global running_offset
    retAddr = loc + 5
    storeByte = retAddr & 0xff
    funcLoc = int(funcStr,16)
    # print(type(funcLoc), hex(funcLoc))
    assert fileBytes[funcLoc:funcLoc+2] == b'\x8f\x05', f"prologue does not match: pop Addr to func\nactual value: {fileBytes[funcLoc:funcLoc+6]}"
    assert fileBytes[funcLoc+6] == 0x50, f"prologue does not match: Push RAX\nactual value: {hex(fileBytes[funcLoc+7])}"
    assert fileBytes[funcLoc+7:funcLoc+9] == b'\x48\xc7', f"prologue does not match: set RAX to zero\nactual value: {fileBytes[funcLoc+7:funcLoc+9+4]}"
    assert fileBytes[funcLoc+14:funcLoc+16] == b'\x8a\x25', f"prologue does not match: set RAX to last retAddr\nActual Value:{fileBytes[funcLoc+14:funcLoc+16+4]} at loc {hex(loc)}, func {funcStr}"
    
    byteAdd = last_call_byte * 0x100
    # if not retAddr == 0x9d:
    last_call_byte = storeByte

    assert fileBytes[funcLoc+20:funcLoc+23] == b'\x67\x8d\x80', f"prologue does not match: Add val into RAX  {fileBytes[funcLoc+20:funcLoc+23]}"

    instrBytes = struct.unpack("<i",fileBytes[funcLoc+23:funcLoc+23+4])[0]

    assert fileBytes[funcLoc+27:funcLoc+27+7] == b'\x89\x05\x01\x00\x00\x00\x58', f"prologue does not match: Alter Instructions & pop RAX  {fileBytes[funcLoc+27:funcLoc+27+7]}"
    
    fileBytes[funcLoc+34:funcLoc+34+4] = struct.pack("<i",instrBytes+byteAdd)

    capEngine = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    for i in capEngine.disasm(fileBytes[funcLoc+34:],funcLoc+34):
        if i.mnemonic == "jmp" and "0x" in i.op_str:
            # print("0x{:x}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str))
            running_offset = int(i.op_str,16)
            return
        elif i.mnemonic == "ret" :
            funcIntercept(i)
            raise NotImplementedError
        elif i.address == funcLoc+34:
            funcIntercept(i)
            # print(i.bytes.hex())
        elif i.mnemonic == "mov" and "rip -" in i.op_str:
            nextOffset = i.address
            break
        else:
            funcIntercept(i)
            nextOffset = i.address
            break

    assert fileBytes[nextOffset:nextOffset+2] == b'\xc7\x05' and fileBytes[nextOffset+3:nextOffset+6] == b'\xff'*3, f"epilogue does not match: move fake value back to instr loc {fileBytes[nextOffset:nextOffset+6]}"
    assert fileBytes[nextOffset+10] == 0x50, f"epilogue does not match: push RAX {hex(fileBytes[nextOffset+10])}"
    assert fileBytes[nextOffset+11:nextOffset+13] == b'\x48\xb8', f"epilogue does not match: set RAX to retAddr {fileBytes[nextOffset+11:nextOffset+13]}"
    assert fileBytes[nextOffset+21:nextOffset+24] == b'\x48\x8d\x40'
    fwdJmp = fileBytes[nextOffset+24]
    running_offset = fwdJmp + retAddr
    return

def hlt_jump(loc,amnt):
    print('hlt at',hex(loc))
    global running_offset
    global regNumContains
    global previousRegNum
    #https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170#struct-unwind_info
    offset_UNWIND_INFO = loc+amnt+2 + ((loc+amnt+2)%2)

    #things that do not change with the unwind info
    assert fileBytes[offset_UNWIND_INFO] & 3 == 1, f"UNWIND_INFO: Version changed, actual val: {(fileBytes[offset_UNWIND_INFO-5:offset_UNWIND_INFO+5].hex())}" # version should always be 1
    assert (fileBytes[offset_UNWIND_INFO]) >> 3 == 1, "Flag changed, not covered"
    assert fileBytes[offset_UNWIND_INFO+1] == 0, f"prologue size is not zero at {offset_UNWIND_INFO}"

    countOfCodes = fileBytes[offset_UNWIND_INFO+2]
    if not ASM_MAKE:
        if countOfCodes == 0:
            print("empty hlt")

    # Well, this does change, fugg
    # if countOfCodes > 1:
        # assert fileBytes[offset_UNWIND_INFO+3] & 0xFFFF == 0, f"Frame register is non-zero at {offset_UNWIND_INFO}, with the number {fileBytes[offset_UNWIND_INFO+3] & 0xFFFF}"
    if countOfCodes > 0:
        assert not (fileBytes[offset_UNWIND_INFO+3] & 0x0F > 15), f"FP register out of scale, at loc {hex(loc)}, unwind at {hex(offset_UNWIND_INFO)}"
        assert not (fileBytes[offset_UNWIND_INFO+3] & 0xF0 > 240), f"FP offset is out of scope, at loc {hex(loc)}, unwind at {hex(offset_UNWIND_INFO)}"

    if fileBytes[offset_UNWIND_INFO+3] & 0xFF != 0:
        if not ASM_MAKE:
            if PRINT_UNWIND:
                print("\t\t\tFP register used at ",end='')
                # assert ((fileBytes[offset_UNWIND_INFO+3] & 0xFFFF) & ((fileBytes[offset_UNWIND_INFO+3] & 0xFFFF) - 1)) == 0, f"More than one bit is set, at loc {hex(loc)}, unwind at {hex(offset_UNWIND_INFO)}"

                print(num2reg[fileBytes[offset_UNWIND_INFO+3] & 0x0F])
        assert fileBytes[offset_UNWIND_INFO+3] & 0xF0 == 0, "offset is not zero"
        # print("FP register offset RSP + ",(fileBytes[offset_UNWIND_INFO+4] & 0xFFFF*16))
            
    # from official documentation.... what?
    # UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1]
    unwindCodesnum = ((countOfCodes + 1) & ~1)
    unwind_code_len = unwindCodesnum * 2
    locJmp = offset_UNWIND_INFO+4+unwind_code_len

    if countOfCodes > 0:
        unwindCodes = fileBytes[offset_UNWIND_INFO+4:locJmp]

        unwindCodeList = [unwindCodes[i:i+2] for i in range(0,unwind_code_len,2)]
        unwindi = 0
        if ASM_MAKE:
            while True:
                if unwindi >= (unwindCodesnum - (unwindCodesnum-countOfCodes)):
                    break

                assert unwindCodeList[unwindi][0] == 0, "unwind code offset not zero, uh oh"
                unwindOp = (unwindCodeList[unwindi][1]&0x0F)
                unwindInfo = (unwindCodeList[unwindi][1]&0xF0)>>4

                match unwindOp:
                    case 0:
                        print("pop ",
                            num2reg[unwindInfo]
                            ,"# unwind_push_nonvol",sep='')
                        unwindi = unwindi + 1
                    case 1:
                        # print("UWOP_ALLOC_LARGE",end='')
                        if (unwindCodeList[unwindi][1]>>4)&0xf== 1:
                            # print(" 3 bytes",end='')
                            value = struct.unpack("<I",unwindCodes[(unwindi+1)*2:(unwindi+1)*2+2*2])[0]
                            unwindi = unwindi + 3
                        elif (unwindCodeList[unwindi][1]>>4)&0xf== 0:
                            # print(" 2 bytes ",end='')
                            value = struct.unpack("<h",unwindCodeList[unwindi+1])[0] * 8
                            unwindi = unwindi + 2
                        else:
                            raise IndexError
                        print("add qword ptr [rsp], ",hex(value),"# unwind_ALLOC_LARGE",sep='')


                    case 2:
                        #fuck it, cant figure it out, and it doesnt seem important.
                        # print("UWOP_ALLOC_SMALL",
                        #     num2reg[unwindInfo]
                        #     )
                        unwindi = unwindi + 1
                    case 3:
                        # print("UWOP_SET_FPREG", num2reg[unwindInfo])
                        print("push ",num2reg[unwindInfo],"# unwind_SET_FPREG",sep='')
                        unwindi = unwindi + 1
                    case 0xa:
                        # print("UWOP_PUSH_MACHFRAME",end='')
                        unwindi = unwindi + 1
                        if unwindInfo == 0:
                            #pops 3
                            print(
    '''pop r9
pop r9
pop r9# unwind_PUSH_MACHFRAME''')
                        elif unwindInfo == 1:
                            #seens to pop 4
                            print(
    '''pop r9
pop r9
pop r9
pop r9# unwind_PUSH_MACHFRAME''')
                            
                        else:
                            raise NotImplementedError
                    case _:
                        print("newOp:",unwindOp)
                        print(unwindCodeList[unwindi][1]&0x0f)
                        raise NotImplementedError
        elif PRINT_UNWIND:
            while True:
                if unwindi >= (unwindCodesnum - (unwindCodesnum-countOfCodes)):
                    break

                assert unwindCodeList[unwindi][0] == 0, "unwind code offset not zero, uh oh"
                unwindOp = (unwindCodeList[unwindi][1]&0x0F)
                unwindInfo = (unwindCodeList[unwindi][1]&0xF0)>>4

                match unwindOp:
                    case 0:
                        print("UWOP_PUSH_NONVOL",
                            num2reg[unwindInfo]
                            )
                        unwindi = unwindi + 1
                    case 1:
                        print("UWOP_ALLOC_LARGE",
                            end=''
                            )
                        if (unwindCodeList[unwindi][1]>>4)&0xf== 1:
                            print(" 3 bytes ",end='')
                            print(hex(struct.unpack("<I",unwindCodes[(unwindi+1)*2:(unwindi+1)*2+2*2])[0]))
                            unwindi = unwindi + 3
                        elif (unwindCodeList[unwindi][1]>>4)&0xf== 0:
                            print(" 2 bytes ",end='')
                            value = struct.unpack("<H",unwindCodes[(unwindi+1)*2:(unwindi+1)*2+1*2])[0]
                            value = value
                            print(hex(value))
                            unwindi = unwindi + 2
                        else :
                            raise NotImplementedError
                    case 2:
                        print("UWOP_ALLOC_SMALL",
                            hex(((unwindCodeList[unwindi][1]>>4)&0xf)*8+8)
                            )
                        unwindi = unwindi + 1
                    case 3:
                        print("UWOP_SET_FPREG",
                            num2reg[unwindInfo]
                            )
                        unwindi = unwindi + 1
                    case 0xa:
                        print("UWOP_PUSH_MACHFRAME",
                                end=''
                            )
                        unwindi = unwindi + 1
                        if unwindInfo == 0:
                            print(
    '''
    RSP+32 	SS
    RSP+24 	Old RSP
    RSP+16 	EFLAGS
    RSP+8 	CS
    RSP 	RIP''')
                        elif unwindInfo == 1:
                            print(
    '''
    RSP+40 	SS
    RSP+32 	Old RSP
    RSP+24 	EFLAGS
    RSP+16 	CS
    RSP+8 	RIP
    RSP 	Error code''')
                            
                        else:
                            raise NotImplementedError

                    case _:
                        print("newOp:",unwindOp)
                        print(unwindCodeList[unwindi][1]&0x0f)
                        raise NotImplementedError
    
    else:
        if not ASM_MAKE:
            print("Empty unwind")
        
    jmpFwdLoc = struct.unpack("<i",fileBytes[locJmp:locJmp+4])[0]
    running_offset = jmpFwdLoc
    previousRegNum = regNumContains
    regNumContains={
            0:  '',
            1:  '',
            2:  '',
            3:  '',
            4:  '',
            5:  '',
            6:  '',
            7:  '',
            8:  '',
            9:  '',
            10: '',
            11: '',
            12: '',
            13: '',
            14: '',
            15: '',
    }
    regNumContains[reg2num['r9']] = 'DISPATCHER_CONTEXT'

    assert jmpFwdLoc < 0x2e4d26, f"Function table length exceeded, value given {hex(jmpFwdLoc)} at {hex(offset_UNWIND_INFO)}" #magic number pulled from binary
    assert jmpFwdLoc > 0, f"relative jump location is negative, value given {fileBytes[locJmp:locJmp+4].hex()} at {hex(offset_UNWIND_INFO)}" #indicates misread jump location


    
    
    if not PRINT_UNWIND:
        print('hlt')
    return




def main():
    global regNumContains
    capEngine = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)

    while True:
        for i in capEngine.disasm(fileBytes[running_offset:],running_offset):
            if i.mnemonic == "hlt":
                hlt_jump(i.address,fileBytes[i.address+1])
                break
            elif i.mnemonic == "call":
                funcBreakdown(i.address, i.op_str)
                break
            else:
                funcIntercept(i)

main()


