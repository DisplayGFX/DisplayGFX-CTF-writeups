import binascii
import struct
import os
import curses

# Constants
HEADER_OFFSET = 0x1000
DATA_START = 0x4040 - HEADER_OFFSET
DATA_LENGTH_WORDS = 4541
PADDING_COUNT = 200
STACK_OFFSET_THRESHOLD = DATA_LENGTH_WORDS * 4
CONST_REG_BASE = 4522
BLOCK_START = 1203

class Instruction:
    """
    Represents a single VM instruction with two registers (a, b) and next instruction pointer.
    """
    def __init__(self, reg_a: int, reg_b: int, next_ip: int):
        self.reg_a = reg_a
        self.reg_b = reg_b
        self.next_ip = next_ip

class TuringMachine:
    """
    A simple VM represented by a list of integers as its program and a program counter.
    """
    def __init__(self, program: list[int], pc: int = 0):
        self.program = program
        self.pc = pc

    @classmethod
    def from_file(cls, filename: str) -> 'TuringMachine':
        """
        Load a binary file, extract encoded program data, and initialize the TuringMachine.
        """
        with open(filename, "rb") as f:
            raw_data = bytearray(f.read())

        # Extract instruction words
        start = DATA_START
        length_bytes = DATA_LENGTH_WORDS * 4
        encoded = raw_data[start: start + length_bytes + 4]
        program = []
        for i in range(0, len(encoded), 4):
            value = struct.unpack('<i', encoded[i:i + 4])[0]
            program.append(value)

        # Pad with negative values to avoid crashing
        for x in range(PADDING_COUNT):
            program.append(-x)

        return cls(program)

    def step(self) -> tuple[int, int, int | None]:
        """
        Execute one VM step. Returns a tuple of (prev_b_value, b_index, old_pc).
        """
        a = self.program[self.pc]
        b = self.program[self.pc + 1]
        next_ip = self.program[self.pc + 2]

        prev_b_val = 0
        old_pc = 0

        # Input instruction: reg_a == -1
        if a == -1:
            prev_b_val = self.program[b]
            char = input("Input required: ")
            if char:
                # Mask out upper bytes, store only low 8 bits
                new_val = (ord(char[0]) & 0xFF) | (self.program[b] & 0xFFFFFF00)
                self.program[b] = new_val
            self.pc += 3

        # Output instruction: reg_b == -1
        elif b == -1:
            out_val = self.program[a] & 0xFF
            print("Output:", chr(out_val))
            self.pc += 3

        # Arithmetic/jump instruction
        else:
            prev_b_val = self.program[b]
            self.program[b] -= self.program[a]
            if self.program[b] < 1:
                if next_ip == -1:
                    print("Exiting...")
                    exit(0)
                old_pc = self.pc
                self.pc = next_ip
            else:
                self.pc += 3

        return prev_b_val, b, old_pc

class MemoryDisplay:
    """
    Handles rendering the VM memory to the terminal using curses.
    """
    def __init__(self, tm: TuringMachine, fixed_cols: int):
        self.tm = tm
        self.start_line = 0
        self.fixed_cols = fixed_cols

    def format_value(self, idx: int, value: int, a_idx: int, b_index: int) -> str:
        """
        Convert a raw integer value into a display string, handling constants, stacks, registers,
        hex region, and ASCII for memory beyond that.
        """
        # Detect stack-related values
        if STACK_OFFSET_THRESHOLD < abs(value) < STACK_OFFSET_THRESHOLD + PADDING_COUNT:
            offset = abs(value) - (STACK_OFFSET_THRESHOLD + 1)
            return f"{'stack+' if value > 0 else 'stack-'}{offset}"

        # Constants and registers in the CONST_REG_BASE range
        if CONST_REG_BASE < value < CONST_REG_BASE + 25:
            reg_map = {
                4523: "neg2_cst", 4524: "zero_cst", 4525: "ten_cst", 4526: "two_cst",
                4527: "three_cst", 4528: "four_cst", 4529: "3_cst", 4530: "blockloc",
                4536: "neg1_cst", 4538: "one_cst",
                4531: "reg_a", 4532: "reg_b", 4533: "reg_c", 4534: "reg_d", 4535: "reg_e",
                4537: "MOV", 4539: "stor?", 4540: "RBP", 4541: "RSP"
            }
            return reg_map.get(value, f"int[{value - CONST_REG_BASE:2}]")

        # Block addresses
        if BLOCK_START <= value < BLOCK_START * 2-1:
            return f"blk[{value - BLOCK_START:2}]"

        # Display hex for memory addresses in the first block
        if BLOCK_START <= idx < BLOCK_START * 2-1:
            return hex(value)

        # Beyond hex region: display low byte as ASCII if printable
        if idx <= BLOCK_START:
            if 32 <= value < 127:
                return chr(value)

        # Default: display decimal
        return str(value)

    def draw(self, stdscr, prev_b_val: int | None, b_index: int, old_pc: int | None, instr_num: int):
        stdscr.clear()
        max_y, max_x = stdscr.getmaxyx()
        prompt = "Press Enter for next step..."

        # Header lines
        header = f"#{instr_num}: PC={self.tm.pc}"
        if old_pc is not None:
            header += f", Jumped from {old_pc}"
        stdscr.addstr(0, 0, header)
        if prev_b_val is not None:
            stdscr.addstr(1, 0, f"Prev B[{b_index}] = {prev_b_val}")

        # Current instruction decode
        idx = self.tm.pc
        a_idx = self.tm.program[idx]
        b_idx = self.tm.program[idx + 1]
        c_val = self.tm.program[idx + 2]
        a_val = self.tm.program[a_idx]
        b_val = self.tm.program[b_idx]
        instr_line = f" Instr: A=prog[{a_idx}]({a_val}) B=prog[{b_idx}]({b_val}) C={c_val}"
        stdscr.addstr(2, 0, instr_line)

        # Render register snapshot at fixed offset
        reg_base = CONST_REG_BASE + 9
        regs = [self.tm.program[reg_base + i] for i in range(5)]
        rsp = self.tm.program[CONST_REG_BASE + 19]
        rbp = self.tm.program[CONST_REG_BASE + 18]
        reg_line = (
            f"RSP={rsp}  A={regs[0]} B={regs[1]} C={regs[2]} D={regs[3]} E={regs[4]} "
            f"MOV={self.tm.program[CONST_REG_BASE + 15]} "
            f"stor={self.tm.program[CONST_REG_BASE + 17]} RBP={rbp}"
        )
        stdscr.addstr(3, 0, reg_line)

        # Draw memory grid with fixed column count
        available_lines = max_y - 5
        start = self.start_line * self.fixed_cols
        end = min(start + available_lines * self.fixed_cols, len(self.tm.program))
        row, col = 4, 0
        for i in range(start, end):
            val_str = self.format_value(i, self.tm.program[i], a_idx, b_index)
            # Highlight special indices
            if i == idx:
                stdscr.addstr(row, col, f"[{val_str:^8}]", curses.color_pair(2))
            elif i == idx + 1:
                stdscr.addstr(row, col, f"({val_str:^8})", curses.color_pair(3))
            elif i == idx + 2:
                stdscr.addstr(row, col, f"<{val_str:^8}>", curses.color_pair(4))
            elif i == a_idx:
                stdscr.addstr(row, col, f"*{val_str:^8}*", curses.color_pair(2))
            elif i == b_idx:
                stdscr.addstr(row, col, f"*{val_str:^8}*", curses.color_pair(3))
            elif i == c_val:
                stdscr.addstr(row, col, f"#{val_str:^8}#", curses.color_pair(4))
            elif b_index is not None and i == b_index:
                stdscr.addstr(row, col, f" {val_str:^8} ", curses.color_pair(1))
            else:
                stdscr.addstr(row, col, f" {val_str:^8} ")
            col += 12
            if col + 12 > max_x:
                col = 0
                row += 1
                if row >= available_lines + 4:
                    break

        # Footer prompt
        stdscr.addstr(max_y - 1, 0, prompt[:max_x])
        stdscr.refresh()
        return True


def main(stdscr):
    # Initialize colors
    curses.start_color()
    curses.init_pair(1, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)

    # Determine fixed column count based on initial window size
    initial_max_x = stdscr.getmaxyx()[1]
    fixed_cols = max(1, initial_max_x // 12)

    # Load and run VM
    tm = TuringMachine.from_file("substandard")
    display = MemoryDisplay(tm, fixed_cols)
    instr_count = 0
    prev_b_val = 0
    b_idx = 0
    old_pc = 0

    while True:
        display.draw(stdscr, prev_b_val, b_idx, old_pc, instr_count)
        key = stdscr.getch()
        if key in (curses.KEY_ENTER, 10):
            prev_b_val, b_idx, old_pc = tm.step()
            instr_count += 1
        elif key == curses.KEY_UP:
            display.start_line = max(0, display.start_line - 1)
        elif key == curses.KEY_DOWN:
            max_lines = (len(tm.program) - 1) // display.fixed_cols
            display.start_line = min(max_lines, display.start_line + 1)
        else:
            # Exit on any other key
            break

if __name__ == "__main__":
    curses.wrapper(main)
