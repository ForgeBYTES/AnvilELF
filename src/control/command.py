from abc import ABC, abstractmethod
from argparse import Namespace

from src.control.argument import ArgumentParser
from src.elf.binary import Binary
from src.elf.executable_header import (
    ExecutableHeader,
    ValidatedExecutableHeader,
)
from src.elf.program_header import (
    ProgramHeader,
    ProgramHeaders,
    ValidatedProgramHeader,
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
from src.elf.section_header import (
    SectionHeader,
    SectionHeaders,
    ValidatedSectionHeader,
    ValidatedSectionHeaders,
)
from src.elf.segment import RawDynamic, Segments, ValidatedDynamic
from src.view.view import (
    FormattedDisassembly,
    FormattedDynamic,
    FormattedExecutableHeader,
    FormattedSection,
    FormattedSections,
    FormattedSegments,
    FormattedSymbolTable,
)


class Command(ABC):
    @abstractmethod
    def name(self) -> str:
        pass  # pragma: no cover

    @abstractmethod
    def output(self, raw_arguments: list[str]) -> str:
        pass  # pragma: no cover


class ExecutableHeaderCommand(Command):
    __NAME = "header"

    def __init__(self, executable_header: ExecutableHeader):
        self.__executable_header = executable_header

    def name(self) -> str:
        return self.__NAME

    def output(self, raw_arguments: list[str]) -> str:
        arguments = self.__arguments(self.__NAME, raw_arguments)
        if arguments.validate:
            ValidatedExecutableHeader(self.__executable_header).validate()
        return FormattedExecutableHeader(
            self.__executable_header, arguments.json
        ).format()

    def __arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-j", "--json", action="store_true", default=False)
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

    def output(self, raw_arguments: list[str]) -> str:
        arguments = self.__arguments(self.__NAME, raw_arguments)
        if arguments.validate:
            ValidatedSectionHeaders(self.__section_headers).validate()
        return FormattedSections(self.__sections, arguments.json).format()

    def __arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-j", "--json", action="store_true", default=False)
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

    def output(self, raw_arguments: list[str]) -> str:
        arguments = self.__arguments(self.__NAME, raw_arguments)
        return FormattedSection(
            self.__sections.find(arguments.name),
            arguments.full,
            arguments.json,
        ).format()

    def __arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-n", "--name", required=True)
        parser.add_argument("-f", "--full", action="store_true", default=False)
        parser.add_argument("-j", "--json", action="store_true", default=False)
        return parser.parse_args(raw_arguments)


class StringTableCommand(Command):
    def __init__(
        self,
        sections: Sections,
        command_name: str,
        section_name: str,
        string_table_name: str,
    ):
        self.__sections = sections
        self.__command_name = command_name
        self.__section_name = section_name
        self.__string_table_name = string_table_name

    def name(self) -> str:
        return self.__command_name

    def output(self, raw_arguments: list[str]) -> str:
        arguments = self.__arguments(self.__command_name, raw_arguments)
        symbol_table = self.__symbol_table(
            self.__sections,
            self.__section_name,
            self.__string_table_name,
        )
        if arguments.validate:
            ValidatedSymbolTable(symbol_table).validate()
        return FormattedSymbolTable(
            symbol_table,
            self.__section_name,
            arguments.json,
        ).format()

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
        parser.add_argument("-j", "--json", action="store_true", default=False)
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

    def output(self, raw_arguments: list[str]) -> str:
        arguments = self.__arguments(self.__command_name, raw_arguments)
        return FormattedDisassembly(
            RawDisassembly(self.__sections.find(self.__section_name)),
            arguments.offset,
            arguments.size,
            arguments.json,
        ).format()

    def __arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-o", "--offset", type=int, default=0)
        parser.add_argument("-s", "--size", type=int, default=0)
        parser.add_argument("-j", "--json", action="store_true", default=False)
        return parser.parse_args(raw_arguments)


class TextCommand(DisassemblyCommand):
    def __init__(self, sections: Sections):
        super().__init__(sections, "text", ".text")


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

    def output(self, raw_arguments: list[str]) -> str:
        arguments = self.__arguments(self.__NAME, raw_arguments)
        if arguments.validate:
            ValidatedProgramHeaders(self.__program_headers).validate()
        return FormattedSegments(self.__segments, arguments.json).format()

    def __arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-j", "--json", action="store_true", default=False)
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

    def output(self, raw_arguments: list[str]) -> str:
        arguments = self.__arguments(self.__NAME, raw_arguments)
        dynamic = RawDynamic(
            self.__segments.occurrence(ProgramHeader.PT_DYNAMIC)
        )
        if arguments.validate:
            ValidatedDynamic(dynamic).validate()
        return FormattedDynamic(dynamic, arguments.json).format()

    def __arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-j", "--json", action="store_true", default=False)
        parser.add_argument(
            "-v", "--validate", action="store_true", default=False
        )
        return parser.parse_args(raw_arguments)


class MutateExecutableHeaderCommand(Command):
    __NAME = "mutate-header"
    __FIELDS = ExecutableHeader.FIELDS + ExecutableHeader.E_INDENT_FIELDS

    def __init__(self, executable_header: ExecutableHeader, binary: Binary):
        self.__executable_header = executable_header
        self.__binary = binary

    def name(self) -> str:
        return self.__NAME

    def output(self, raw_arguments: list[str]) -> str:
        arguments = self._arguments(self.__NAME, raw_arguments)
        self.__mutate(
            (
                ValidatedExecutableHeader(self.__executable_header)
                if arguments.validate
                else self.__executable_header
            ),
            arguments.field,
            arguments.value,
        )
        self.__binary.save()
        return f"Field '{arguments.field}' mutated to {arguments.value}"

    def __mutate(
        self, executable_header: ExecutableHeader, field: str, value: int
    ) -> None:
        fields = executable_header.fields()
        if field in ExecutableHeader.E_INDENT_FIELDS:
            fields["e_ident"][field] = value
        else:
            fields[field] = value
        executable_header.change(fields)

    def _arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument(
            "-f",
            "--field",
            choices=[
                field
                for field in self.__FIELDS
                if field not in ["ei_mag", "ei_pad"]
            ],
            required=True,
        )
        parser.add_argument(
            "-V", "--value", type=lambda x: int(x, 0), required=True
        )
        parser.add_argument(
            "-v", "--validate", action="store_true", default=False
        )
        return parser.parse_args(raw_arguments)


class MutateSectionHeaderCommand(Command):
    __NAME = "mutate-section-header"
    __FIELDS = SectionHeader.FIELDS

    def __init__(
        self,
        sections: Sections,
        section_headers: SectionHeaders,
        binary: Binary,
    ):
        self.__sections = sections
        self.__section_headers = section_headers
        self.__binary = binary

    def name(self) -> str:
        return self.__NAME

    def output(self, raw_arguments: list[str]) -> str:
        arguments = self._arguments(self.__NAME, raw_arguments)
        section_header = self.__sections.find(arguments.section).header()
        self.__mutate(
            (
                ValidatedSectionHeader(section_header, self.__section_headers)
                if arguments.validate
                else section_header
            ),
            arguments.field,
            arguments.value,
        )
        self.__binary.save()
        return f"Field '{arguments.field}' mutated to {arguments.value}"

    def __mutate(
        self, section_header: SectionHeader, field: str, value: int
    ) -> None:
        fields = section_header.fields()
        fields[field] = value
        section_header.change(fields)

    def _arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-s", "--section", required=True)
        parser.add_argument(
            "-f", "--field", choices=self.__FIELDS, required=True
        )
        parser.add_argument(
            "-V", "--value", type=lambda x: int(x, 0), required=True
        )
        parser.add_argument(
            "-v", "--validate", action="store_true", default=False
        )
        return parser.parse_args(raw_arguments)


class MutateProgramHeaderCommand(Command):
    __NAME = "mutate-program-header"
    __FIELDS = ProgramHeader.FIELDS

    def __init__(self, segments: Segments, binary: Binary):
        self.__segments = segments
        self.__binary = binary

    def name(self) -> str:
        return self.__NAME

    def output(self, raw_arguments: list[str]) -> str:
        arguments = self._arguments(self.__NAME, raw_arguments)
        program_header = self.__segments.find(arguments.offset).header()
        self.__mutate(
            (
                ValidatedProgramHeader(program_header)
                if arguments.validate
                else program_header
            ),
            arguments.field,
            arguments.value,
        )
        self.__binary.save()
        return f"Field '{arguments.field}' mutated to {arguments.value}"

    def __mutate(
        self, program_header: ProgramHeader, field: str, value: int
    ) -> None:
        fields = program_header.fields()
        fields[field] = value
        program_header.change(fields)

    def _arguments(self, name: str, raw_arguments: list[str]) -> Namespace:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument(
            "-o", "--offset", type=lambda x: int(x, 0), required=True
        )
        parser.add_argument(
            "-f", "--field", choices=self.__FIELDS, required=True
        )
        parser.add_argument(
            "-V", "--value", type=lambda x: int(x, 0), required=True
        )
        parser.add_argument(
            "-v", "--validate", action="store_true", default=False
        )
        return parser.parse_args(raw_arguments)
