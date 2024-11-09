import re

def deblackbox(val:int):
    match val:
        case 0x1400942c0:
            box_str = "x_AND_y"
        case 0x140094ac0:
            box_str = 'x_XOR_y'
        case 0x1400952c0:
            box_str = 'x_OR_y'
        case 0x140095ac0:
            box_str = 'x+y_AND_0xff'
        case 0x1400962c0:
            box_str = '255-x_greater_than_y_bitset'
        case 0x140096ac0:
            box_str = 'y_minus_x'
        case 0x1400972c0:
            box_str = 'x_greater_then_y_bitset'
        case 0x14089b8e8:
            box_str = 'in_flag'
        case 0x1400011f0:
            box_str = "wrong_flag"
        case 0x1400011b0:
            box_str = "correct_flag"
        case _:
            box_str = hex(val)
            print(box_str)
            raise NotImplementedError
    return box_str

# Function to handle the replacement
def replace_movabs_add(match):
    movabs_value = int(match.group(1), 16)
    add_value = int(match.group(2), 16)
    
    total_value = movabs_value + add_value
    box_str = deblackbox(total_value)
    return f'whitebox {box_str}'

def replace_pushstack(match):
    movabs_value = int(match.group(1), 16)
    add_value = int(match.group(2), 16)
    
    total_value = movabs_value + add_value
    box_str = deblackbox(total_value)
    return f'whitebox {box_str}'

with open('instr.txt',"r") as x:
    text = x.read()

movabs_add_pattern = r'\bmovabs\s+\w+,\s+(0x[0-9a-fA-F]+)\b\n0x[0-9a-fA-F]+:\s+add\s+\w+,\s+(0x[0-9a-fA-F]+)\b'
pushstack_pattern = r'\bmovabs\s+\w+,\s+(0x[0-9a-fA-F]+)\b\n(?:.*push.*\n)*0x[0-9a-fA-F]+: \tadd qword ptr \[rsp \+ 0x[0-9a-fA-F]+\], (0x[0-9a-fA-F]+)'

result = re.sub(movabs_add_pattern, replace_movabs_add, text)
result = re.sub(pushstack_pattern, replace_pushstack,result)

print(result)

