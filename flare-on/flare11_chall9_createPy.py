import re

with open("whiteinst.txt","r") as x:
    data = x.read()

lines = data.splitlines()
results = []

for i, line in enumerate(lines):
    if 'mul qword ptr [rsp]' in line:
        mov_value = None
        add_value = None
        uwop_alloc_value = None
        
        for j in range(i-1, max(i-10,0), -1):
            if 'add' in lines[j] and add_value is None:
                add_match = re.search(r'add [^,]+, (0x[0-9a-fA-F]+)', lines[j])
                if add_match:
                    add_value = int(add_match.group(1), 16)
            if 'mov' in lines[j] and mov_value is None:
                mov_match = re.search(r'mov [^,]+, (0x[0-9a-fA-F]+)', lines[j])
                if mov_match:
                    mov_value = int(mov_match.group(1), 16)
            if mov_value is not None and add_value is not None:
                break

        for k in range(i, max(i-30, 0), -1):
            if 'UWOP_ALLOC_LARGE' in lines[k]:
                uwop_match = re.search(r'UWOP_ALLOC_LARGE . bytes (0x[0-9a-fA-F]+)', lines[k])
                if uwop_match:
                    uwop_alloc_value = int(uwop_match.group(1), 16)
                break
            elif 'UWOP_ALLOC_SMALL' in lines[k]:
                uwop_match = re.search(r'UWOP_ALLOC_SMALL (0x[0-9a-fA-F]+)', lines[k])
                if uwop_match:
                    uwop_alloc_value = int(uwop_match.group(1), 16)
                break


        charOp = '?'

        charopLine = lines[i+7]
        charMatch = re.search(r'0x[0-9a-fA-F\ ]+: \t\b([A-Za-z]+)\b',charopLine)
        charOp = charMatch.group(1)
        match charOp:
            case "sub":
                charOp = '-'
            case "xor":
                charOp = '^'
            case "add" | "push":
                charOp = '+'


        arrayOp = '?'
        arrayConst = '0xXXXXXXXX'
        #arrayop finding
        arrayOpMatch = None
        for m in range(i, i+80):
            try:
                if "whitebox" in lines[m]:
                    arrayOpMatch = re.search(r'0x[\s0-9a-f]{6}: \twhitebox \b([\w\-]+)\b',lines[m])
                    if arrayOpMatch:
                        arrayOp = arrayOpMatch.group(1)
                        match arrayOp:
                            case 'x_XOR_y':
                                arrayOp = '^'
                            case 'x_greater_then_y_bitset':
                                arrayOp = '-'
                            case '255-x_greater_than_y_bitset':
                                arrayOp = '+'
                        break
            except:
                arrayOp = 'X('
                if len(results) == 254:
                    pass
                else:
                    print("err",(m),len(results))
                pass

        if arrayOp == '+':
            const1 = 'whitebox x+y_AND_0xff'
        elif arrayOp == '-':
            const1 = 'whitebox y_minus_x'
        elif arrayOp == '^':
            const1 = 'whitebox x_XOR_y'

        pos = 0
        trueval = 0
        for n in range (i,i+1000):
            try:
                if const1 in lines[n]:
                    for o in range(n,n+15):
                        if 'UWOP_ALLOC_LARGE' in lines[o]:
                            pos += 1
                            hexval = int(lines[o][25:],16)
                            if lines[o][17] == '3':
                                hexval = hexval // 8
                            hexval = hexval << (pos-1)*8
                            trueval += hexval
                            break
                        if 'UWOP_ALLOC_SMALL' in lines[o]:
                            pos += 1
                            break
                    if pos == 4:
                        break
            except:
                arrayOp = 'X('
                if len(results) == 254:
                    pass
                else:
                    print("err",(m),len(results))
                pass

        arrayConst = hex(trueval)
    

        if mov_value is not None and add_value is not None:
            if uwop_alloc_value is None:
                uwop_alloc_value = 0
            result = {
                'char' :  uwop_alloc_value,
                'charOp' : charOp,
                'mov + add': hex((mov_value + add_value)&0xffffffffff),
                'arrayOp': arrayOp,
                'arrayConst': arrayConst,
                'extraOp':'?',
                'extraConst':'0x?',
            }
            results.append(result)
    if 'test' in line:
        extraOp = 'TOUCH'
        count= 0
        trueval=0
        for y in range(i,max(0,i-10000),-1):
            if "whitebox" in lines[y]:
                if 'y_minus_x' in lines[y]:
                    count += 1
                    if count == 1:
                        extraOp = '-'
                        for z in range(y,y+15):
                            if 'UWOP_ALLOC_LARGE' in lines[z] and ('0xff' in lines[z] or '0x7f8' in lines[z]):
                                extraOp = '+'
                                break
                    if count > 1 and extraOp == '+':
                        for z in range(y,y+15):
                            if 'UWOP_ALLOC_LARGE' in lines[z]:
                                if '3 bytes' in lines[z]:
                                    hexval = int(lines[z][25:],16)//8
                                else:
                                    hexval = int(lines[z][25:],16)
                                pos = 8-count
                                realval = (hexval^0xff)<<pos*8
                                trueval += realval
                                break
                    if count > 1 and count < 7 and extraOp == '-':
                        for z in range(y,y+15):
                            if 'UWOP_ALLOC_LARGE' in lines[z]:
                                if '3 bytes' in lines[z]:
                                    hexval = int(lines[z][25:],16)//8
                                else:
                                    hexval = int(lines[z][25:],16)
                                pos = max(5-count,0)
                                realval = (hexval)<<pos*8
                                trueval += realval
                                break
                    if count == 8:
                        break
        res = results.pop()
        res['extraOp'] = extraOp
        res['extraConst'] = hex(trueval)
        results.append(res)


for idx, result in enumerate(results):
    if idx % 8 == 0:
        print(f"def check{(idx//8)+1}(userflag):")
    print(f"\tsum {result['charOp']}= userflag[{result['char']:02d}] * {result['mov + add']}")
    print(f"\tsum {result['arrayOp']}= {result['arrayConst']}")
    if idx % 8 == 7 and idx != 0:
        print(f"\tsum {result['extraOp']}= {result['extraConst']} + ADJUST")
        print("\tsum &= 0xffffffffffffffff")
        print('\treturn sum\n\n\n')
