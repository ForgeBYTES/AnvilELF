from abc import ABC, abstractmethod
from argparse import Namespace

from src.control.argument import ArgumentParser
from src.elf.executable_header import (
    ExecutableHeader,
    ValidatedExecutableHeader,
)
from src.elf.program_header import (
    ProgramHeader,
    ProgramHeaders,
    ValidatedProgramHeaders,
)
from src.elf.section import (
    RawDisassembly,
    RawStringTable,
    RawSymbolTable,
    Sections,
    SymbolTable,
    ValidatedSymbolTable,
)
from src.elf.section_header import SectionHeaders, ValidatedSectionHeaders
from src.elf.segment import RawDynamic, Segments, ValidatedDynamic
from src.view.view import (
    PrintableDisassembly,
    PrintableDynamic,
    PrintableExecutableHeader,
    PrintableSection,
    PrintableSections,
    PrintableSegments,
    PrintableSymbolTable,
)


class Command(ABC):
    @abstractmethod
    def name(self) -> str:
        pass  # pragma: no cover

    @abstractmethod
    def execute(self, raw_arguments: list[str]) -> None:
        pass  # pragma: no cover


class ExecutableHeaderCommand(Command):
    __NAME = "header"

    def __init__(self, executable_header: ExecutableHeader):
        self.__executable_header = executable_header

    def name(self) -> str:
        return self.__NAME

    def execute(self, raw_arguments: list[str]) -> None:
        arguments = self.__arguments(self.__NAME, raw_arguments)
        if arguments.validate:
            ValidatedExecutableHeader(self.__executable_header).validate()
        PrintableExecutableHeader(self.__executable_header).print()

    def __arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument(
            "-v", "--validate", action="store_true", default=False
        )
        return parser.parse_args(raw_arguments)


class SectionsCommand(Command):
    __NAME = "sections"

    def __init__(self, sections: Sections, section_headers: SectionHeaders):
        self.__sections = sections
        self.__section_headers = section_headers

    def name(self) -> str:
        return self.__NAME

    def execute(self, raw_arguments: list[str]) -> None:
        arguments = self.__arguments(self.__NAME, raw_arguments)
        if arguments.validate:
            ValidatedSectionHeaders(self.__section_headers).validate()
        PrintableSections(self.__sections, full=arguments.full).print()

    def __arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-f", "--full", action="store_true", default=False)
        parser.add_argument(
            "-v", "--validate", action="store_true", default=False
        )
        return parser.parse_args(raw_arguments)


class SectionCommand(Command):
    __NAME = "section"

    def __init__(self, sections: Sections):
        self.__sections = sections

    def name(self) -> str:
        return self.__NAME

    def execute(self, raw_arguments: list[str]) -> None:
        arguments = self.__arguments(self.__NAME, raw_arguments)
        PrintableSection(
            self.__sections.find(arguments.name), arguments.full
        ).print()

    def __arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-n", "--name", required=True)
        parser.add_argument("-f", "--full", action="store_true", default=False)
        return parser.parse_args(raw_arguments)


class TextCommand(Command):
    __NAME = "text"

    def __init__(self, sections: Sections):
        self.__sections = sections

    def name(self) -> str:
        return self.__NAME

    def execute(self, raw_arguments: list[str]) -> None:
        arguments = self.__arguments(self.__NAME, raw_arguments)
        PrintableDisassembly(
            RawDisassembly(self.__sections.find(".text")),
            arguments.offset,
            arguments.size,
        ).print()

    def __arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-o", "--offset", type=int, default=0)
        parser.add_argument("-s", "--size", type=int)
        return parser.parse_args(raw_arguments)


class StringTableCommand(Command):
    def __init__(
        self,
        sections: Sections,
        command_name: str,
        section_name: str,
        string_table_name: str,
        validated: bool = False,
    ):
        self.__sections = sections
        self.__command_name = command_name
        self.__section_name = section_name
        self.__string_table_name = string_table_name
        self.__validated = validated

    def name(self) -> str:
        return self.__command_name

    def execute(self, raw_arguments: list[str]) -> None:
        arguments = self.__arguments(self.__command_name, raw_arguments)
        symbol_table = self.__symbol_table(
            self.__sections,
            self.__section_name,
            self.__string_table_name,
        )
        if arguments.validate:
            ValidatedSymbolTable(symbol_table).validate()
        PrintableSymbolTable(
            symbol_table,
            self.__section_name,
        ).print()

    def __symbol_table(
        self,
        sections: Sections,
        section_name: str,
        string_table_name: str,
    ) -> SymbolTable:
        return RawSymbolTable(
            sections.find(section_name),
            RawStringTable(sections.find(string_table_name)),
        )

    def __arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument(
            "-v", "--validate", action="store_true", default=False
        )
        return parser.parse_args(raw_arguments)


class DynsymCommand(StringTableCommand):
    def __init__(self, sections: Sections):
        super().__init__(sections, "dynsym", ".dynsym", ".dynstr")


class SymtabCommand(StringTableCommand):
    def __init__(self, sections: Sections):
        super().__init__(sections, "symtab", ".symtab", ".strtab")


class DisassemblyCommand(Command):
    def __init__(
        self, sections: Sections, command_name: str, section_name: str
    ):
        self.__sections = sections
        self.__command_name = command_name
        self.__section_name = section_name

    def name(self) -> str:
        return self.__command_name

    def execute(self, raw_arguments: list[str]) -> None:
        PrintableDisassembly(
            RawDisassembly(self.__sections.find(self.__section_name))
        ).print()


class PltCommand(DisassemblyCommand):
    def __init__(self, sections: Sections):
        super().__init__(sections, "plt", ".plt")


class InitCommand(DisassemblyCommand):
    def __init__(self, sections: Sections):
        super().__init__(sections, "init", ".init")


class FiniCommand(DisassemblyCommand):
    def __init__(self, sections: Sections):
        super().__init__(sections, "fini", ".fini")


class SegmentsCommand(Command):
    __NAME = "segments"

    def __init__(self, segments: Segments, program_headers: ProgramHeaders):
        self.__segments = segments
        self.__program_headers = program_headers

    def name(self) -> str:
        return self.__NAME

    def execute(self, raw_arguments: list[str]) -> None:
        arguments = self.__arguments(self.__NAME, raw_arguments)
        if arguments.validate:
            ValidatedProgramHeaders(self.__program_headers).validate()
        PrintableSegments(self.__segments, arguments.full).print()

    def __arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-f", "--full", action="store_true", default=False)
        parser.add_argument(
            "-v", "--validate", action="store_true", default=False
        )
        return parser.parse_args(raw_arguments)


class DynamicCommand(Command):
    __NAME = "dynamic"

    def __init__(self, segments: Segments):
        self.__segments = segments

    def name(self) -> str:
        return self.__NAME

    def execute(self, raw_arguments: list[str]) -> None:
        arguments = self.__arguments(self.__NAME, raw_arguments)
        dynamic = RawDynamic(
            self.__segments.occurrence(ProgramHeader.PT_DYNAMIC)
        )
        if arguments.validate:
            ValidatedDynamic(dynamic).validate()
        PrintableDynamic(dynamic).print()

    def __arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument(
            "-v", "--validate", action="store_true", default=False
        )
        return parser.parse_args(raw_arguments)
