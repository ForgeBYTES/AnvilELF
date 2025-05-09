from abc import ABC, abstractmethod
from argparse import Namespace

from src.control.argument import ArgumentParser
from src.elf.executable_header import ExecutableHeader
from src.elf.program_header import ProgramHeader
from src.elf.section import (
    RawDisassembly,
    RawStringTable,
    RawSymbolTable,
    Sections,
    SymbolTable,
    ValidatedSymbolTable,
)
from src.elf.segment import (
    Dynamic,
    RawDynamic,
    Segment,
    Segments,
    ValidatedDynamic,
)
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
        PrintableExecutableHeader(self.__executable_header).print()


class SectionsCommand(Command):
    __NAME = "sections"

    def __init__(self, sections: Sections):
        self.__sections = sections

    def name(self) -> str:
        return self.__NAME

    def execute(self, raw_arguments: list[str]) -> None:
        arguments = self.__arguments(self.__NAME, raw_arguments)
        PrintableSections(self.__sections, full=arguments.full).print()

    def __arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-f", "--full", action="store_true")
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
        PrintableSymbolTable(
            self.__symbol_table(
                self.__sections,
                self.__section_name,
                self.__string_table_name,
                self.__validated,
            ),
            self.__section_name,
        ).print()

    def __symbol_table(
        self,
        sections: Sections,
        section_name: str,
        string_table_name: str,
        validated: bool,
    ) -> SymbolTable:
        symbol_table = RawSymbolTable(
            sections.find(section_name),
            RawStringTable(sections.find(string_table_name)),
        )
        if validated:
            return ValidatedSymbolTable(symbol_table)
        return symbol_table


class DynsymCommand(StringTableCommand):
    def __init__(self, sections: Sections, validated: bool = False):
        super().__init__(sections, "dynsym", ".dynsym", ".dynstr", validated)


class SymtabCommand(StringTableCommand):
    def __init__(self, sections: Sections, validated: bool = False):
        super().__init__(sections, "symtab", ".symtab", ".strtab", validated)


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

    def __init__(self, segments: Segments):
        self.__segments = segments

    def name(self) -> str:
        return self.__NAME

    def execute(self, raw_arguments: list[str]) -> None:
        arguments = self.__arguments(self.__NAME, raw_arguments)
        PrintableSegments(self.__segments, full=arguments.full).print()

    def __arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-f", "--full", action="store_true")
        return parser.parse_args(raw_arguments)


class DynamicCommand(Command):
    __NAME = "dynamic"

    def __init__(self, segments: Segments, validated: bool = False):
        self.__segments = segments
        self.__validated = validated

    def name(self) -> str:
        return self.__NAME

    def execute(self, raw_arguments: list[str]) -> None:
        for segment in self.__segments.all():
            if segment.header()["p_type"] == ProgramHeader.PT_DYNAMIC:
                PrintableDynamic(self.__dynamic(segment)).print()
                return
        raise ValueError("Segment PT_DYNAMIC not found")  # pragma: no cover

    def __dynamic(self, segment: Segment) -> Dynamic:
        dynamic = RawDynamic(segment)
        return ValidatedDynamic(dynamic) if self.__validated else dynamic
