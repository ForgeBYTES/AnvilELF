from argparse import Namespace

from src.control.argument import ArgumentParser
from src.control.command import (
    DynamicCommand,
    DynsymCommand,
    ExecutableHeaderCommand,
    FiniCommand,
    InitCommand,
    PltCommand,
    SectionCommand,
    SectionsCommand,
    SegmentsCommand,
    SymtabCommand,
    TextCommand,
)
from src.control.command_line import (
    CommandLine,
    HistoricalCommandLine,
    InteractiveCommandLine,
)
from src.elf.binary import Binary, RawBinary, ValidatedBinary


class Application:
    def __init__(self, argv: list[str], intro: str, hint: str):
        self.__argv = argv
        self.__intro = intro
        self.__hint = hint

    def command_line(self) -> CommandLine:
        try:
            print(self.__intro)
            arguments = self.__arguments(self.__argv)
            (
                executable_header,
                section_headers,
                sections,
                program_headers,
                segments,
            ) = self.__binary(arguments).components()
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
                        SymtabCommand(sections, arguments.validate),
                        DynsymCommand(sections, arguments.validate),
                        SegmentsCommand(segments),
                        DynamicCommand(segments, arguments.validate),
                    ],
                )
            )
        except ValueError as error:
            print(error)
            raise SystemExit(1)

    def __binary(self, arguments: Namespace) -> Binary:
        return (
            ValidatedBinary(RawBinary(arguments.binary))
            if arguments.validate
            else RawBinary(arguments.binary)
        )

    def __arguments(self, argv: list[str]) -> Namespace:
        parser = ArgumentParser(add_help=False)
        parser.add_argument("binary")
        parser.add_argument("-v", "--validate", action="store_true")
        return parser.parse_args(argv[1:])
