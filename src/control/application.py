from src.control.command import (
    DynsymCommand,
    ExecutableHeaderCommand,
    FiniCommand,
    InitCommand,
    PltCommand,
    SectionCommand,
    SectionsCommand,
    SymtabCommand,
    TextCommand,
)
from src.control.command_line import (
    CommandLine,
    HistoricalCommandLine,
    InteractiveCommandLine,
)
from src.elf.binary import RawBinary, ValidatedBinary


class Application:
    __BINARY_PATH = 1

    def __init__(self, argv: list, intro: str, usage: str, hint: str):
        self.__argv = argv
        self.__intro = intro
        self.__usage = usage
        self.__hint = hint

    def command_line(self) -> CommandLine:
        try:
            print(self.__intro)

            executable_header, section_headers, sections = ValidatedBinary(
                RawBinary(self.__binary_path(self.__argv))
            ).components()

            return HistoricalCommandLine(
                InteractiveCommandLine(
                    self.__hint,
                    [
                        ExecutableHeaderCommand(executable_header),
                        SectionsCommand(sections),
                        SectionCommand(sections),
                        TextCommand(sections),
                        PltCommand(sections),
                        InitCommand(sections),
                        FiniCommand(sections),
                        SymtabCommand(sections),
                        DynsymCommand(sections),
                    ],
                )
            )
        except ValueError as error:
            print(error)
            raise SystemExit(1)

    def __binary_path(self, argv: list) -> str:
        try:
            return argv[self.__BINARY_PATH]
        except IndexError:
            print(self.__usage)
            raise SystemExit(1)
