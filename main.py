from sys import argv

from src.control.command import (
    ExecutableHeaderCommand,
    SectionCommand,
    SectionsCommand,
    TextCommand,
)
from src.control.command_line import (
    HistoricalCommandLine,
    InteractiveCommandLine,
)
from src.elf.executable_header import (
    CachedExecutableHeader,
    RawExecutableHeader,
    ValidatedExecutableHeader,
)
from src.elf.section import CachedSections
from src.elf.section_header import (
    CachedSectionHeaders,
    RawSectionHeaders,
    ValidatedSectionHeaders,
)

INTRO = """
 ▗▄▖ ▗▖  ▗▖▗▖  ▗▖▗▄▄▄▖▗▖   ▗▄▄▄▖▗▖   ▗▄▄▄▖
▐▌ ▐▌▐▛▚▖▐▌▐▌  ▐▌  █  ▐▌   ▐▌   ▐▌   ▐▌
▐▛▀▜▌▐▌ ▝▜▌▐▌  ▐▌  █  ▐▌   ▐▛▀▀▘▐▌   ▐▛▀▀▘
▐▌ ▐▌▐▌  ▐▌ ▝▚▞▘ ▗▄█▄▖▐▙▄▄▖▐▙▄▄▖▐▙▄▄▖▐▌

From raw bytes to forged ELF—crafted with purist OOP.

Inspect your binary ⚒️
Forge your binary 🔥
"""

HINT = """
header                        Show executable header
sections [--full]             List all sections
section -n NAME [-full]       Show section by name
text [--offset N] [--size N]  Disassemble .text section
exit                          Exit the shell
"""

if __name__ == "__main__":
    try:
        print(INTRO)
        with open(argv[1], "rb") as binary:
            raw_data = bytearray(binary.read())

        executable_header = CachedExecutableHeader(
            ValidatedExecutableHeader(RawExecutableHeader(raw_data))
        )
        section_headers = CachedSectionHeaders(
            ValidatedSectionHeaders(
                RawSectionHeaders(raw_data, executable_header)
            )
        )
        sections = CachedSections(
            raw_data,
            section_headers,
            executable_header,
        )

        HistoricalCommandLine(
            InteractiveCommandLine(
                HINT,
                [
                    ExecutableHeaderCommand(executable_header),
                    SectionsCommand(sections),
                    SectionCommand(sections),
                    TextCommand(sections),
                ],
            )
        ).run()
    except IndexError:
        print("[Info] Usage: python main.py <binary>")
    except OSError as error:
        print(f"[Error] Failed to load binary: '{error.strerror}'")
