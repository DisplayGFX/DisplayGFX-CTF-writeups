Sudoking
===

HTB Challenge

Place Achieved: #226

By DisplayGFX
___
Description
```
Welcome to the SUDOku Tournament! Conquer all puzzles in record time to claim the title of SUDOking and rule the grid!
```
## Initial Enumeration

There are no files, only a website.
```
	
SudoKing

Welcome to the SudoKing challenge! In this task, your objective is to write a program that solves a given Sudoku puzzle.

Challenge Description:

    You will receive an incomplete Sudoku puzzle as input.
    Your program must solve the puzzle and output the completed Sudoku grid.
    The input and output will be formatted with box separators to clearly delineate the 3x3 subgrids.
    Ensure that your output matches the required format exactly, including the box separators and line breaks.

Note: You only need to print the correctly solved Sudoku puzzle. Do not include any additional text or debugging information in your output.
Example
Input

+-------+-------+-------+
| . . 1 | 2 7 5 | . 9 6 |
| 8 5 . | 6 . 3 | 4 . . |
| . . . | . 1 4 | 3 . 2 |
+-------+-------+-------+
| . 3 . | . . . | 7 . . |
| . 2 8 | 3 . . | 9 6 . |
| . 7 . | 9 2 . | 1 . 5 |
+-------+-------+-------+
| . . . | . 4 . | . . 1 |
| 9 . 5 | . . . | 2 4 3 |
| 4 . 7 | . 3 . | . . . |
+-------+-------+-------+

Output


+-------+-------+-------+
| 2 4 1 | 2 7 5 | 8 9 6 |
| 8 5 6 | 6 4 3 | 4 1 2 |
| 7 9 3 | 5 1 4 | 3 8 2 |
+-------+-------+-------+
| 5 3 2 | 1 8 9 | 7 6 4 |
| 6 2 8 | 3 5 7 | 9 6 1 |
| 4 7 9 | 9 2 6 | 1 3 5 |
+-------+-------+-------+
| 3 6 8 | 4 4 2 | 5 7 1 |
| 9 1 5 | 7 6 8 | 2 4 3 |
| 4 8 7 | 2 3 1 | 6 5 9 |
+-------+-------+-------+
```

## Solving the Sudo

Considering that this challenge is about solving sudoku, and I am an impatient hacker, I decided to use a premade python file.

https://github.com/dhhruv/Sudoku-Solver/blob/master/sudokutools.py

Simply copy-paste the relevant functions, and that is halfway there.

The other half is formatting. apparently, the program will be VERY picky if you do not have your whitespace aligned correctly. Again, impatient hacker, I want to get to the good stuff, not formatting, and messing with whitespaces and rendering. So I tasked chatgpt (o3-mini-high) with a couple of prompts and feedback, and this is what I got.

```python
def grid_to_array(grid_str: str) -> list[list[int]]:
    """
    Converts a string representation of a Sudoku grid into a 2D list of integers.
    Empty cells (represented by '.') are converted to 0.
    
    Example grid string format:
    +-------+-------+-------+
    | . . 1 | 2 7 5 | . 9 6 |
    ... [rest of grid] ...
    +-------+-------+-------+
    """
    rows = []
    for line in grid_str.splitlines():
        line = line.strip()
        # Process only lines that represent rows (those starting with "|")
        if line and line[0] == "|":
            # Split the row into segments and remove extra whitespace
            parts = [part.strip() for part in line.split("|") if part.strip()]
            row = []
            for part in parts:
                # Each segment contains numbers or dots separated by spaces.
                for token in part.split():
                    row.append(0 if token == '.' else int(token))
            rows.append(row)
    return rows


def array_to_grid(array: list[list[int]]) -> str:
    """
    Converts a 2D list of integers into a string representation of a Sudoku grid.
    
    The output format will be similar to:
    +-------+-------+-------+
    | 2 4 1 | 2 7 5 | 8 9 6 | 
    ... [rest of grid] ...
    +-------+-------+-------+
    """
    lines = []
    horizontal_line = "+-------+-------+-------+"
    for i, row in enumerate(array):
        # Insert a horizontal border every 3 rows
        if i % 3 == 0:
            lines.append(horizontal_line)
        row_str = ""
        for j, num in enumerate(row):
            # Insert vertical borders every 3 columns
            if j % 3 == 0:
                row_str += "| "
            row_str += f"{num} "
        # Append vertical bar and trailing space for the row
        row_str += "| "
        lines.append(row_str)
    lines.append(horizontal_line)
    return "\n".join(lines)


def find_empty(board):
    """
    Finds the first empty cell (represented by 0) in the Sudoku board.
    Returns a tuple (row, col) or None if no empty cell is found.
    """
    for i in range(9):
        for j in range(9):
            if board[i][j] == 0:
                return (i, j)
    return None


def valid(board, pos, num):
    """
    Checks whether placing the given number at the given position is valid
    according to Sudoku rules.
    """
    # Check column
    for i in range(9):
        if board[i][pos[1]] == num:
            return False

    # Check row
    for j in range(9):
        if board[pos[0]][j] == num:
            return False

    # Check 3x3 sub-box
    start_i = pos[0] - pos[0] % 3
    start_j = pos[1] - pos[1] % 3
    for i in range(3):
        for j in range(3):
            if board[start_i + i][start_j + j] == num:
                return False
    return True


def solve(board):
    """
    Solves the sudoku board using the backtracking algorithm.
    Returns True if the board is solvable, otherwise False.
    """
    empty = find_empty(board)
    if not empty:
        return True

    for num in range(1, 10):
        if valid(board, empty, num):
            board[empty[0]][empty[1]] = num
            if solve(board):  # recursive step
                return True
            board[empty[0]][empty[1]] = 0  # backtrack
    return False


if __name__ == "__main__":
    # Read input grid (first line plus 12 more lines)
    n = input()
    for _ in range(12):
        n += "\n" + input()
    arr = grid_to_array(n)
    solve(arr)
    print(array_to_grid(arr), end='')
```

And the flag is in the success message!

[https://labs.hackthebox.com/achievement/challenge/158887/835]
