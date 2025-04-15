import struct
from abc import ABC, abstractmethod
from functools import cached_property

import capstone

from src.elf.executable_header import ExecutableHeader
from src.elf.section_header import SectionHeader, SectionHeaders


class Section(ABC):
    @abstractmethod
    def header(self) -> dict:
        pass  # pragma: no cover

    @abstractmethod
    def data(self) -> bytes:
        pass  # pragma: no cover

    @abstractmethod
    def name(self) -> str:
        pass  # pragma: no cover


class Sections(ABC):
    @abstractmethod
    def all(self) -> list[Section]:
        pass  # pragma: no cover


class Shstrtab(Section):
    @abstractmethod
    def name_by_index(self, sh_name: int) -> str:
        pass  # pragma: no cover


class Disassemblable(Section):
    @abstractmethod
    def disassembly(self) -> list[str]:
        pass  # pragma: no cover


class Symbol(ABC):
    @abstractmethod
    def fields(self) -> dict:
        pass  # pragma: no cover

    @abstractmethod
    def name(self) -> str:
        pass  # pragma: no cover

    @abstractmethod
    def bind(self):
        pass  # pragma: no cover

    @abstractmethod
    def type(self):
        pass  # pragma: no cover

    @abstractmethod
    def visibility(self):
        pass  # pragma: no cover


class SymbolTable(Section):
    @abstractmethod
    def all(self) -> list[Symbol]:
        pass  # pragma: no cover


class RawSection(Section):
    def __init__(
        self,
        raw_data: bytearray,
        header: SectionHeader,
        shstrtab: Shstrtab | None = None,
    ):
        self.__raw_data = raw_data
        self.__section_header = header
        self.__shstrtab = shstrtab

    def header(self) -> dict:
        return self.__section_header.fields()

    def data(self) -> bytes:
        fields = self.__section_header.fields()
        return self.__raw_data[
            fields["sh_offset"] : fields["sh_offset"]  # noqa: E203
            + fields["sh_size"]
        ]

    def name(self) -> str:
        if self.__shstrtab is None:
            return str(self.__section_header.fields()["sh_name"])

        return self.__shstrtab.name_by_index(
            self.__section_header.fields()["sh_name"]
        )


class RawShstrtabSection(Shstrtab):
    def __init__(self, origin: Section):
        self.__origin = origin

    def name_by_index(self, sh_name: int) -> str:
        data = self.data()
        return data[
            sh_name : data.find(b"\x00", sh_name)  # noqa: E203
        ].decode("ascii")

    def header(self) -> dict:
        return self.__origin.header()  # pragma: no cover

    def data(self) -> bytes:
        return self.__origin.data()

    def name(self) -> str:
        return ".shstrtab"  # pragma: no cover


class RawSymbol(Symbol):
    __STRUCT_FORMAT = "<IBBHQQ"

    def __init__(self, data: bytes, offset: int, string_table: Section):
        self.__data = data
        self.__offset = offset
        self.__string_table = string_table

    def fields(self) -> dict:
        _struct = struct.unpack_from(
            self.__STRUCT_FORMAT,
            self.__data,
            self.__offset,
        )
        return {
            "st_name": _struct[0],
            "st_info": _struct[1],
            "st_other": _struct[2],
            "st_shndx": _struct[3],
            "st_value": _struct[4],
            "st_size": _struct[5],
        }

    def name(self) -> str:
        data = self.__string_table.data()
        st_name = self.fields()["st_name"]
        return data[
            st_name : data.find(b"\x00", st_name)  # noqa: E203
        ].decode("utf-8")

    def bind(self):
        return self.fields()["st_info"] >> 4

    def type(self):
        return self.fields()["st_info"] & 0xF

    def visibility(self):
        return self.fields()["st_other"] & 0x3


class RawSymbolTable(SymbolTable):
    __ENTRY_SIZE = 24

    def __init__(self, origin: Section, string_table: Section):
        self.__origin = origin
        self.__string_table = string_table

    def all(self) -> list[Symbol]:
        data = self.__origin.data()
        return [
            RawSymbol(data, offset, self.__string_table)
            for offset in range(0, len(data), self.__ENTRY_SIZE)
        ]

    def header(self) -> dict:
        return self.__origin.header()  # pragma: no cover

    def data(self) -> bytes:
        return self.__origin.data()  # pragma: no cover

    def name(self) -> str:
        return self.__origin.name()  # pragma: no cover


class DisassembledSection(Disassemblable):
    __SHF_EXECINSTR = 0x4

    def __init__(self, origin: Section):
        self.__origin = origin
        self.__cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def disassembly(self) -> list[str]:
        header = self.header()
        if self.__is_executable(header):
            self.__cs.syntax = capstone.CS_OPT_SYNTAX_INTEL
            return [
                self.__instruction(
                    instruction.address,
                    instruction.mnemonic,
                    instruction.op_str,
                )
                for instruction in self.__cs.disasm(
                    self.data(),
                    header["sh_addr"],
                )
            ]
        raise ValueError("Section is not executable")

    def header(self) -> dict:
        return self.__origin.header()

    def data(self) -> bytes:
        return self.__origin.data()

    def name(self) -> str:
        return self.__origin.name()  # pragma: no cover

    def __is_executable(self, header: dict) -> bool:
        return header["sh_flags"] & self.__SHF_EXECINSTR

    def __instruction(self, address: str, mnemonic: str, op: str):
        return f"{address:08x}: {mnemonic} {op}".rstrip()


class RawSections(Sections):
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
            RawSection(
                self.__raw_data,
                header,
                RawShstrtabSection(
                    RawSection(self.__raw_data, headers[e_shstrndx])
                ),
            )
            for header in headers
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
                    RawShstrtabSection(
                        CachedSection(
                            RawSection(self.__raw_data, headers[e_shstrndx])
                        )
                    ),
                )
            )
            for header in headers
        ]
