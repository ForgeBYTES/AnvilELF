import sys

from src.control.application import Application

intro = """
 ▗▄▖ ▗▖  ▗▖▗▖  ▗▖▗▄▄▄▖▗▖   ▗▄▄▄▖▗▖   ▗▄▄▄▖
▐▌ ▐▌▐▛▚▖▐▌▐▌  ▐▌  █  ▐▌   ▐▌   ▐▌   ▐▌
▐▛▀▜▌▐▌ ▝▜▌▐▌  ▐▌  █  ▐▌   ▐▛▀▀▘▐▌   ▐▛▀▀▘
▐▌ ▐▌▐▌  ▐▌ ▝▚▞▘ ▗▄█▄▖▐▙▄▄▖▐▙▄▄▖▐▙▄▄▖▐▌

From raw bytes to forged ELF—crafted with purist OOP.

Inspect your binary ⚒️
Forge your binary 🔥
"""

usage = "Usage: python main.py <binary>"
hint = """
header                        Show executable header
sections [--full]             List all sections
section -n NAME [-full]       Show section by name
text [--offset N] [--size N]  Disassemble .text section
plt                           Disassemble .plt section
init                          Disassemble .init section
fin                           Disassemble .fin section
dynsym                        Show .dynsym section
symtab                        Show .symtab section
exit                          Exit the shell
"""

if __name__ == "__main__":  # pragma: no cover
    Application(sys.argv, intro, usage, hint).command_line().run()
