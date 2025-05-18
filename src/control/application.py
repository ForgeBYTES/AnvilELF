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
from src.elf.binary import RawBinary


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
            ) = RawBinary(arguments.binary).components()
            return HistoricalCommandLine(
                InteractiveCommandLine(
                    self.__hint,
                    [
                        ExecutableHeaderCommand(executable_header),
                        SectionsCommand(sections, section_headers),
                        SectionCommand(sections),
                        TextCommand(sections),
                        PltCommand(sections),
                        InitCommand(sections),
                        FiniCommand(sections),
                        SymtabCommand(sections),
                        DynsymCommand(sections),
                        SegmentsCommand(segments, program_headers),
                        DynamicCommand(segments),
                    ],
                )
            )
        except ValueError as error:
            print(error)
            raise SystemExit(1)

    def __arguments(self, argv: list[str]) -> Namespace:
        parser = ArgumentParser(add_help=False)
        parser.add_argument("binary")
        return parser.parse_args(argv[1:])
