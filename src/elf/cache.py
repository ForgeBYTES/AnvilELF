from functools import cached_property

from src.elf.executable_header import ExecutableHeader
from src.elf.section import (
    RawSection,
    RawStringTable,
    RawSymbol,
    Section,
    Sections,
    StringTable,
    Symbol,
    SymbolTable,
)
from src.elf.section_header import SectionHeader, SectionHeaders


class CachedExecutableHeader(ExecutableHeader):
    def __init__(self, origin: ExecutableHeader):
        self.__origin = origin

    def fields(self) -> dict:
        return self.__cached_fields

    def change(self, fields: dict) -> None:
        self.__origin.change(fields)

    @cached_property
    def __cached_fields(self) -> dict:
        return self.__origin.fields()


class CachedSectionHeader(SectionHeader):
    def __init__(self, origin: SectionHeader):
        self.__origin = origin

    def fields(self) -> dict:
        return self.__cached_fields

    def change(self, fields: dict) -> None:
        self.__origin.change(fields)

    @cached_property
    def __cached_fields(self) -> dict:
        return self.__origin.fields()


class CachedSectionHeaders(SectionHeaders):
    def __init__(self, origin: SectionHeaders):
        self.__origin = origin

    def all(self) -> list[SectionHeader]:
        return [
            CachedSectionHeader(section) for section in self.__origin.all()
        ]


class CachedSection(Section):
    def __init__(self, origin: Section):
        self.__origin = origin

    def name(self) -> str:
        return self.__cached_name

    def data(self) -> bytes:
        return self.__cached_data

    def header(self) -> dict:
        return self.__cached_header  # pragma: no cover

    @cached_property
    def __cached_name(self) -> str:
        return self.__origin.name()

    @cached_property
    def __cached_data(self) -> bytes:
        return self.__origin.data()

    @cached_property
    def __cached_header(self) -> dict:
        return self.__origin.header()  # pragma: no cover


class CachedSymbol(Symbol):
    def __init__(self, origin: Symbol):
        self.__origin = origin

    def fields(self) -> dict:
        return self.__cached_fields

    def name(self) -> str:
        return self.__cached_name

    def bind(self):
        return self.__cached_bind

    def type(self):
        return self.__cached_type

    def visibility(self):
        return self.__cached_visibility

    @cached_property
    def __cached_fields(self) -> dict:
        return self.__origin.fields()

    @cached_property
    def __cached_name(self) -> str:
        return self.__origin.name()

    @cached_property
    def __cached_bind(self) -> str:
        return self.__origin.bind()

    @cached_property
    def __cached_type(self) -> str:
        return self.__origin.type()

    @cached_property
    def __cached_visibility(self) -> str:
        return self.__origin.visibility()


class CachedSymbolTable(SymbolTable):
    def __init__(self, section: Section, string_table: StringTable):
        self.__section = section
        self.__string_table = string_table

    def symbols(self) -> list[Symbol]:
        data = self.__section.data()
        return [
            CachedSymbol(RawSymbol(data, offset, self.__string_table))
            for offset in range(0, len(data), self._ENTRY_SIZE)
        ]


class CachedSections(Sections):
    def __init__(
        self,
        raw_data: bytearray,
        section_headers: SectionHeaders,
        executable_header: ExecutableHeader,
    ):
        self.__raw_data = raw_data
        self.__section_headers = section_headers
        self.__executable_header = executable_header

    def all(self) -> list[Section]:
        headers = self.__section_headers.all()
        e_shstrndx = self.__executable_header.fields()["e_shstrndx"]
        return [
            CachedSection(
                RawSection(
                    self.__raw_data,
                    header,
                    RawStringTable(
                        CachedSection(
                            RawSection(self.__raw_data, headers[e_shstrndx])
                        )
                    ),
                )
            )
            for header in headers
        ]

    def find(self, name: str) -> Section:
        for section in self.all():
            if section.name() == name:
                return CachedSection(section)
        raise ValueError(f"Section '{name}' not found")
