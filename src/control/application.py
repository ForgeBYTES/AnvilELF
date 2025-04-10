from abc import ABC, abstractmethod

from src.control.command import (
    ExecutableHeaderCommand,
    SectionCommand,
    SectionsCommand,
    TextCommand,
)
from src.control.command_line import (
    CommandLine,
    HistoricalCommandLine,
    InteractiveCommandLine,
)
from src.control.input import ArgvFile, HandledArgvFile
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


class Application(ABC):
    @abstractmethod
    def command_line(self) -> CommandLine:
        pass  # pragma: no cover


class AnvilELF(Application):
    def __init__(self, argv: list, intro: str, usage: str, hint: str):
        self.__argv = argv
        self.__intro = intro
        self.__usage = usage
        self.__hint = hint

    def command_line(self):
        print(self.__intro)
        try:
            raw_data = HandledArgvFile(
                ArgvFile(self.__argv), self.__usage
            ).raw_data()

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

            return HistoricalCommandLine(
                InteractiveCommandLine(
                    self.__hint,
                    [
                        ExecutableHeaderCommand(executable_header),
                        SectionsCommand(sections),
                        SectionCommand(sections),
                        TextCommand(sections),
                    ],
                )
            )
        except ValueError as error:
            print(error)
            raise SystemExit(1)
