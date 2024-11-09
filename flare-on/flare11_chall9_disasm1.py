import capstone
import struct
import re
stack = []

ASM_MAKE = False
if ASM_MAKE:
    print(".intel_syntax noprefix")

running_offset = 0
last_call_byte = 0x4B
with open("../serpentine.exe","rb") as x:
    fileBytes = bytearray(x.read()[0x95ef0:0x800000+0x95ef0])

PRINT_UNWIND = True

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


def instPrint(i:capstone.CsInsn):
    print("0x{:6x}:".format(i.address),"\t",end='')
    print("{} {}".format(i.mnemonic, i.op_str))

def funcBreakdown(loc,funcStr):
    global last_call_byte
    global running_offset
    retAddr = loc + 5
    storeByte = retAddr & 0xff
    funcLoc = int(funcStr,16)
    # block of asserts
    # these bytes in the function will always remain the same
    assert fileBytes[funcLoc:funcLoc+2] == b'\x8f\x05', f"prologue does not match: pop Addr to func\nactual value: {fileBytes[funcLoc:funcLoc+6]}"
    assert fileBytes[funcLoc+6] == 0x50, f"prologue does not match: Push RAX\nactual value: {hex(fileBytes[funcLoc+7])}"
    assert fileBytes[funcLoc+7:funcLoc+9] == b'\x48\xc7', f"prologue does not match: set RAX to zero\nactual value: {fileBytes[funcLoc+7:funcLoc+9+4]}"
    assert fileBytes[funcLoc+14:funcLoc+16] == b'\x8a\x25', f"prologue does not match: set RAX to last retAddr\nActual Value:{fileBytes[funcLoc+14:funcLoc+16+4]} at loc {hex(loc)}, func {funcStr}"
    assert fileBytes[funcLoc+20:funcLoc+23] == b'\x67\x8d\x80', f"prologue does not match: Add val into RAX  {fileBytes[funcLoc+20:funcLoc+23]}"
    assert fileBytes[funcLoc+27:funcLoc+27+7] == b'\x89\x05\x01\x00\x00\x00\x58', f"prologue does not match: Alter Instructions & pop RAX  {fileBytes[funcLoc+27:funcLoc+27+7]}"


    byteAdd = last_call_byte * 0x100
    last_call_byte = storeByte
    instrBytes = struct.unpack("<i",fileBytes[funcLoc+23:funcLoc+23+4])[0]
    fileBytes[funcLoc+34:funcLoc+34+4] = struct.pack("<i",instrBytes+byteAdd)

    capEngine = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    for i in capEngine.disasm(fileBytes[funcLoc+34:],funcLoc+34):
        if i.mnemonic == "mov" and "rip -" in i.op_str:
            nextOffset = i.address
            break

        instPrint(i)
        
        if i.mnemonic == "jmp" and "0x" in i.op_str:
            running_offset = int(i.op_str,16)
            return
        elif i.address == funcLoc+34:
            continue
        else:
            nextOffset = i.address
            break

    #epilogue block
    # these bytes do not change in the function, only their positon compared to the length of the instruction
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
    #https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170#struct-unwind_info
    offset_UNWIND_INFO = loc+amnt+2 + ((loc+amnt+2)%2)

    #things that do not change with the unwind info
    assert fileBytes[offset_UNWIND_INFO] & 3 == 1, f"UNWIND_INFO: Version changed, actual val: {(fileBytes[offset_UNWIND_INFO-5:offset_UNWIND_INFO+5].hex())}" # version should always be 1
    assert (fileBytes[offset_UNWIND_INFO]) >> 3 == 1, "Flag changed, not covered"
    assert fileBytes[offset_UNWIND_INFO+1] == 0, f"prologue size is not zero at {offset_UNWIND_INFO}"
    assert fileBytes[offset_UNWIND_INFO+3] & 0xF0 == 0, "FP Register offset is not zero"

    unwindCodeCnt = fileBytes[offset_UNWIND_INFO+2]
    if unwindCodeCnt > 0:
        assert not (fileBytes[offset_UNWIND_INFO+3] & 0x0F > 15), f"FP register out of scale, at loc {hex(loc)}, unwind at {hex(offset_UNWIND_INFO)}"
        assert not (fileBytes[offset_UNWIND_INFO+3] & 0xF0 > 240), f"FP offset is out of scope, at loc {hex(loc)}, unwind at {hex(offset_UNWIND_INFO)}"

    if fileBytes[offset_UNWIND_INFO+3] & 0xFF != 0:
        if PRINT_UNWIND:
            print("\t\t\tFP register used at ",end='')
            print(num2reg[fileBytes[offset_UNWIND_INFO+3] & 0x0F])
            
    # from official documentation
    # UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1]
    # this ensures theres an even number of UnwindCode slots
    # unwindCodeCnt, while accurate, isnt used
    unwindCodeSlots = ((unwindCodeCnt + 1) & ~1)
    unwind_code_len = unwindCodeSlots * 2
    locJmp = offset_UNWIND_INFO+4+unwind_code_len

    if unwindCodeCnt > 0:
        unwindCodes = fileBytes[offset_UNWIND_INFO+4:locJmp]

        unwindCodeList = [unwindCodes[i:i+2] for i in range(0,unwind_code_len,2)]
        unwindi = 0
        if PRINT_UNWIND:
            while True:
                if unwindi >= (unwindCodeSlots - (unwindCodeSlots-unwindCodeCnt)):
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
        if PRINT_UNWIND:
            print("Empty unwind")
        
    jmpFwdLoc = struct.unpack("<i",fileBytes[locJmp:locJmp+4])[0]
    running_offset = jmpFwdLoc

    assert jmpFwdLoc < 0x2e4d26, f"Function table length exceeded, value given {hex(jmpFwdLoc)} at {hex(offset_UNWIND_INFO)}" #magic number pulled from binary
    assert jmpFwdLoc > 0, f"relative jump location is negative, value given {fileBytes[locJmp:locJmp+4].hex()} at {hex(offset_UNWIND_INFO)}" #indicates misread jump location

    return




def main():
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
                instPrint(i)

main()


