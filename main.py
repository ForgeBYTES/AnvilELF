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

hint = """
header [-v] [-j]                                              Show executable header
sections [-v] [-j]                                            List all sections
section -n NAME [-full] [-j]                                  Show section by name
segments [-v] [-j]                                            List all segments
dynamic [-v] [-j]                                             Show PT_DYNAMIC segment
text [-o N] [-s N] [-j]                                       Disassemble .text section
plt [-j]                                                      Disassemble .plt section
init [-j]                                                     Disassemble .init section
fin [-j]                                                      Disassemble .fin section
dynsym [-v] [-j]                                              Inspect .dynsym section
symtab [-v] [-j]                                              Inspect .symtab section
mutate-header -f FIELD -V VALUE [-v]                          Mutate executable header
mutate-section-header -f FIELD -V VALUE [-v]                  Mutate section header
mutate-program-header -f FIELD -V VALUE [-v]                  Mutate program header
mutate-symbol -s SYMBOL_TABLE -n NAME -f FIELD -V VALUE [-v]  Mutate program header
replace-section -s SECTION -b BYTES                           Replace section data
replace-segment -o OFFSET -b BYTES                            Replace segment data
exit                                                          Exit the shell
"""

if __name__ == "__main__":  # pragma: no cover
    Application(sys.argv, intro, hint).command_line().run()
