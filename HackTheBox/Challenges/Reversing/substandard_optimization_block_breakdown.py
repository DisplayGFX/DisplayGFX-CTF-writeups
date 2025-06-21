import struct
import matplotlib.pyplot as plt
import numpy as np

# Constants for file parsing
HEADER_OFFSET = 0x1000
DATA_START = 0x4040 - HEADER_OFFSET
DATA_LENGTH_WORDS = 4541
PADDING_COUNT = 20  # padding count for overkill

# Constant and register value mappings
CONST_BASE = 4522
CONST_MAP = {
    CONST_BASE + 1: "neg2_cst", CONST_BASE + 2: "zero_cst", CONST_BASE + 3: "ten_cst", CONST_BASE + 4: "two_cst",
    CONST_BASE + 5: "three_c1", CONST_BASE + 6: "four_cst", CONST_BASE + 7: "three_c2", CONST_BASE + 8: "blockloc",
    CONST_BASE + 14: "neg1_cst", CONST_BASE + 16: "one_cst",
    CONST_BASE + 9: "reg_a", CONST_BASE + 10: "reg_b", CONST_BASE + 11: "reg_c", CONST_BASE + 12: "reg_d", CONST_BASE + 13: "reg_e",
    CONST_BASE + 15: "MOV", CONST_BASE + 17: "stor_reg", CONST_BASE + 18: "RBP", CONST_BASE + 19: "RSP"
}

# Instruction comments mapped by index
COMMENTS = {
    2433: "# sets RSP to RBP, makes space for 2",
    2439: "# push reg_a",
    2466: "# push reg_b",
    2494: "# push reg_c",
    2520: "# reg_c = reg_b = RBP[-2] = val[RBP[3] + RBP[2]]",
    2562: ("# if RBP[-2]/reg_b == 1: stor_reg = 0; jump 3085 "
            "else: jump 2599"),
    2598: "# reg_c = reg_b = RBP[-2]",
    2649: ("# if RBP[-2] == 2: reg_b = 1; jump 3085 "
            "else: continue"),
    2676: "# RBP[-1] = 1",
    2727: "# reg_c = reg_b = RBP[-2]",
    2778: ("# if RBP[-2] == 0: jump 2998 "
            "else: continue"),
    2784: "# reg_c = reg_b = RBP[-2]",
    2835: "# RBP[-2] = RBP[-2] - 1",
    2889: "# reg_c = RBP[-1]",
    2928: "# reg_b = -RBP[-1]",
    2946: "# RBP[-1] = -RBP[-1]",
    2997: "# reg_a = -RBP[-1]; reg_c = RBP[-1]; reg_b = RBP[-1]",
    3048: ("# if (RBP[-1] == 1) { stor_reg = 0 } else { if (RBP[-1] > 1) { reg_b = 0 }; stor_reg = 1 }"),
    3084: "# pop reg_c; pop reg_b; pop reg_a",
    3165: "# main_func: pushes RBP to stack",
    3192: "# init RBP stack, moves RSP up to give 5 values for RBP",
    3204: "# sets reg_a to RSP stack",
    3228: "# sets reg_b to RSP stack",
    3255: "# sets reg_c to RSP stack",
    3282: "# sets reg_d to RSP stack",
    3309: "# sets reg_e to RSP stack",
    3336: "# moves 3 into RBPstack[1]",
    3387: "# moves blockloc onto RBPstack[2]",
    3438: "# moves 0 onto RBPstack[3]",
    3489: "# jump: RBP[3] > Blocklen - 1",
    3546: "# if false, get RBPStack[2] into reg_d",
    3585: "# get RBPStack[3] into reg_e",
    3624: "# RBPStack[3] + RBPStack[2] into reg_c",
    3639: "# val[RBPStack[3] + RBPStack[2]] into reg_e",
    3663: ("# push result (counter + blockloc) to stack; "
            "set reg_a, reg_b, reg_c, reg_d, reg_e, RSP, stor_reg accordingly"),
    3724: "# RBP[4] = reg_e",
    3730: "# post call instr",
    3733: "# sets RBP[4] to -stor_reg",
    3784: "# gets RBP[4]",
    3853: "# reg_c = RBP[1]",
    3898: "# reg_d = RBP[3]",
    3937: "# reg_b = RBP[1] + RBP[3]",
    3952: "# reg_d = val[RBP[3] + RBP[1]]",
    3970: "# val[RBP[3] + RBP[1]] pushed to stack",
    4003: "# call printchr; RSP[-1] = val[RBP[3] + RBP[1]]",
    3835: ("# this took too long; if RBP[4] == 1 continue; "
            "else: reg_b = 0; jmp 4099"),
    4488: ("# Init block; call 3316; set reg_a, reg_b, reg_c, reg_d, reg_e, stor_reg, RBP appropriately"),
    4034: "# Calls printchr(LF/newline)",
    4037: "# newline (LF=10) pushed to stack",
    4067: "# return location pushed to stack",
    4091: "# call printchr(LF/newline)",
    4098: "# increments RBP[3], starts loop again",
    4131: "# moves RSP[0] (returned val) into reg_e",
    4143: "# moves RSP[-1] into reg_d",
    4158: "# moves RSP[-2] into reg_c",
    4173: "# moves RSP[-3] into reg_b",
    4188: "# moves RSP[-4] into reg_a",
    4128: "# jumps to 3490",
    4212: "# moves RSP[0] into RBP",
    4224: "# returns to caller",
    4242: ("# printchar subroutine: takes RSP[-1], stor_reg -= char; "
            "push RBP, set RSP, push reg_a, reg_b, reg_c, print, stor_reg, pop regs, pop RSP, return"),
    4269: "# set RSP to RBP",
    4275: "# push reg_a",
    4302: "# push reg_b",
    4329: "# push reg_c",
    4356: "# PRINT RSP[-1]",
    4398: "# stor_reg = -RSP[-1]",
    4404: "# pop reg_c",
    4420: "# pop reg_b",
    4434: "# pop reg_a",
    4449: "# pop RSP, reset RSP",
    4470: "# return to caller"
}


def load_program(filename: str) -> list[int]:
    """
    Load binary data from file, decode 32-bit little-endian signed integers,
    and append padding values.
    """
    with open(filename, "rb") as f:
        data = bytearray(f.read())

    start = DATA_START
    byte_length = DATA_LENGTH_WORDS * 4
    encoded = data[start : start + byte_length + 4]

    program: list[int] = []
    for i in range(0, len(encoded), 4):
        value = struct.unpack('<i', encoded[i : i + 4])[0]
        program.append(value)

    # Pad with large negative values to avoid crashes
    for i in range(PADDING_COUNT):
        program.append(-((1 << 32) - 1) * (i + 1))

    return program


def map_value_to_label(x: int) -> str:
    """
    Convert a raw integer x to a human-readable label.
    """
    # Special markers
    if x == -1:
        return "special"
    if x == 0:
        return "0"
    if x == 2403:
        return "blocklen"
    if x == 4243:
        return "printchr"

    # Memory or constant region
    if x > CONST_BASE:
        if x in CONST_MAP:
            return CONST_MAP[x]
        if x > CONST_BASE and x < CONST_BASE + 20:
            return f"int[{x - CONST_BASE}]"
        if x > DATA_LENGTH_WORDS:
            return f"mem_{abs(x) - DATA_LENGTH_WORDS}"

    # ASCII region
    if 2 < x < 1203:
        return f"chr[{x}]"

    # Block labels
    if 1203 <= x < 2403:
        return f"blk[{x}]"

    # Default: decimal
    return str(x)


def print_initial_blocks(program: list[int]) -> None:
    """
    Print the initial instruction block (first 3 values), ASCII block (3 to 1202),
    and hex block (1203 to 2402).
    """
    print("Initial Instruction Block:")
    for idx in range(3):
        print(program[idx], end="  ")
    print("\n")

    print("ASCII Block (indices 3..1202):")
    for x in program[3:1203]:
        print(chr(x), end="")
    print("\n\n")

    print("Hex Block (indices 1203..2402):")
    for x in program[1203:2403]:
        print(hex(x), end=" ")
    print("\n")


def print_program_block(program: list[int]) -> None:
    """
    Print labeled instructions for the main program block (2404..4522) in a single-line format.
    """
    print("Start of Program Block:")
    for idx in range(2404, 4523, 3):
        # Insert comment if present
        if idx in COMMENTS:
            print(f"{COMMENTS[idx]}")
        if idx+1 in COMMENTS:
            print(f"{COMMENTS[idx+1]}")
        if idx+2 in COMMENTS:
            print(f"{COMMENTS[idx+2]}")
        a = program[idx]
        b = program[idx + 1]
        nxt = program[idx + 2]

        a_label = map_value_to_label(a)
        b_label = map_value_to_label(b)
        nxt_label = map_value_to_label(nxt)

        print(f"loc {idx}: {a_label:<12} {b_label:<8} {nxt_label}")
    print("\nEnd of Program Block.\n")


def print_stack_and_constants(program: list[int]) -> None:
    """
    Print the stack or constant blocks (indices 3..1202 and 1203..2402) in formatted arrays.
    """
    stack_vals = program[3:1203]
    const_vals = program[1203:2403]

    print("Block of ascii Values (formatted):")
    for i in range(0, len(stack_vals), 30):
        print(stack_vals[i : i + 30])
    print("\n")

    print("Block of Constant Values (formatted):")
    for i in range(0, len(const_vals), 20):
        print(const_vals[i : i + 20])
    print("\n")


def print_constants(program: list[int]) -> None:
    """
    Print constant region values (indices 4523..4541).
    """
    print("Constants Region:")
    for idx in range(4523, 4542):
        print(f"{program[idx]:8}", end=" ")
    print("\n")


def plot_value_distribution(values: list[int]) -> None:
    """
    Plot a histogram of value distribution.
    """
    values_array = np.array(values)
    plt.figure(figsize=(10, 6))
    plt.hist(values_array, bins=200, edgecolor='black', alpha=0.7)
    plt.title('Value Distribution in Turing Machine Tape')
    plt.xlabel('Value')
    plt.ylabel('Frequency')
    plt.show()


def plot_scatter_distribution(values: list[int]) -> None:
    """
    Plot a scatter of values versus their indices.
    """
    values_array = np.array(values)
    indices = np.arange(len(values_array))
    plt.figure(figsize=(12, 6))
    plt.scatter(indices, values_array, alpha=0.6, edgecolors='w', s=50)
    plt.title('Scatter Plot of Value Distribution in Turing Machine Tape')
    plt.xlabel('Position in Array')
    plt.ylabel('Value')
    plt.show()


def main():
    program = load_program("substandard")

    # Display initial blocks
    print_initial_blocks(program)

    # Display program instructions with labels
    print_program_block(program)

    # Display stack and constant arrays
    print_stack_and_constants(program)

    # Display constants region
    print_constants(program)

    # Optional: plot distributions (commented out by default)
    # cipherblock = [x for x in program[1203:2403]]
    # plot_scatter_distribution(cipherblock)

if __name__ == "__main__":
    main()
