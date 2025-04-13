import sys

from src.control.application import AnvilELF

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
exit                          Exit the shell
"""

if __name__ == "__main__":  # pragma: no cover
    AnvilELF(sys.argv, intro, usage, hint).command_line().run()
