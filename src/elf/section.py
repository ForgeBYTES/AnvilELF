import struct
from abc import ABC, abstractmethod

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

    @abstractmethod
    def find(self, name: str) -> Section:
        pass  # pragma: no cover


class StringTable(Section):
    @abstractmethod
    def name_by_index(self, sh_name: int) -> str:
        pass  # pragma: no cover


class Disassemblable(Section):
    @abstractmethod
    def disassembly(self) -> list[str]:
        pass  # pragma: no cover


class Symbol(ABC):
    _FIELDS = [
        "st_name",
        "st_info",
        "st_other",
        "st_shndx",
        "st_value",
        "st_size",
    ]

    _STB_LOCAL = 0
    _STB_GLOBAL = 1
    _STB_WEAK = 2
    _STB_LOOS = 10
    _STB_HIOS = 12
    _STB_LOPROC = 13
    _STB_HIPROC = 15

    # fmt: off
    _BINDS = [
        _STB_LOCAL, _STB_GLOBAL, _STB_WEAK, _STB_LOOS,
        _STB_HIOS, _STB_LOPROC, _STB_HIPROC,
    ]
    # fmt: on

    _STT_NOTYPE = 0
    _STT_OBJECT = 1
    _STT_FUNC = 2
    _STT_SECTION = 3
    _STT_FILE = 4
    _STT_COMMON = 5
    _STT_TLS = 6
    _STT_LOOS = 10
    _STT_HIOS = 12
    _STT_LOPROC = 13
    _STT_HIPROC = 15

    # fmt: off
    _TYPES = [
        _STT_NOTYPE, _STT_OBJECT, _STT_FUNC, _STT_SECTION, _STT_FILE,
        _STT_COMMON, _STT_TLS, _STT_LOOS, _STT_HIOS, _STT_LOPROC,
        _STT_HIPROC,
    ]
    # fmt: on

    _STV_DEFAULT = 0
    _STV_INTERNAL = 1
    _STV_HIDDEN = 2
    _STV_PROTECTED = 3

    _VISIBILITIES = [
        _STV_DEFAULT,
        _STV_INTERNAL,
        _STV_HIDDEN,
        _STV_PROTECTED,
    ]

    _SHN_UNDEF = 0
    _SHN_ABS = 0xFFF1
    _SHN_COMMON = 0xFFF2

    _SPECIAL_SHNDX = [
        _SHN_UNDEF,
        _SHN_ABS,
        _SHN_COMMON,
    ]

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
    _ENTRY_SIZE = 24

    @abstractmethod
    def symbols(self) -> list[Symbol]:
        pass  # pragma: no cover


class RawSection(Section):
    def __init__(
        self,
        raw_data: bytearray,
        header: SectionHeader,
        shstrtab: StringTable | None = None,
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


class RawStringTable(StringTable):
    def __init__(self, origin: Section):
        self.__origin = origin

    def name_by_index(self, sh_name: int) -> str:
        data = self.data()
        return data[
            sh_name : data.find(b"\x00", sh_name)  # noqa: E203
        ].decode("utf-8", errors="replace")

    def header(self) -> dict:
        return self.__origin.header()  # pragma: no cover

    def data(self) -> bytes:
        return self.__origin.data()

    def name(self) -> str:
        return self.__origin.name()  # pragma: no cover


class RawSymbol(Symbol):
    __STRUCT_FORMAT = "<IBBHQQ"

    def __init__(self, data: bytes, offset: int, string_table: StringTable):
        self.__data = data
        self.__offset = offset
        self.__string_table = string_table

    def fields(self) -> dict:
        return dict(
            zip(
                self._FIELDS,
                struct.unpack_from(
                    self.__STRUCT_FORMAT,
                    self.__data,
                    self.__offset,
                ),
            )
        )

    def name(self) -> str:
        return self.__string_table.name_by_index(self.fields()["st_name"])

    def bind(self):
        return self.fields()["st_info"] >> 4

    def type(self):
        return self.fields()["st_info"] & 0xF

    def visibility(self):
        return self.fields()["st_other"] & 0x3


class ValidatedSymbol(Symbol):
    def __init__(self, origin: Symbol):
        self.__origin = origin

    def fields(self) -> dict:
        fields = self.__origin.fields()
        self.__validate(fields)
        return fields

    def name(self) -> str:
        return self.__origin.name()

    def bind(self):
        return self.__origin.bind()

    def type(self):
        return self.__origin.type()

    def visibility(self):
        return self.__origin.visibility()

    def __validate(self, fields: dict):
        for field, value in fields.items():
            match field:
                case "st_info":
                    _type = value & 0xF
                    bind = value >> 4
                    if bind in self._BINDS and _type in self._TYPES:
                        continue
                case "st_other":
                    visibility = value & 0x3
                    if visibility in self._VISIBILITIES:
                        continue
                case "st_shndx":
                    if 0 <= value <= 0xFFFF:
                        continue
                case _:
                    self.__validate_field_exists(field, self._FIELDS)
                    continue

            raise ValueError(f"Invalid value for {field}")  # pragma: no cover

    def __validate_field_exists(self, field: str, fields: list):
        if field not in fields:
            raise ValueError(f"Unknown field {field}")  # pragma: no cover


class RawSymbolTable(SymbolTable):
    def __init__(self, origin: Section, string_table: StringTable):
        self.__origin = origin
        self.__string_table = string_table

    def symbols(self) -> list[Symbol]:
        data = self.__origin.data()
        return [
            RawSymbol(data, offset, self.__string_table)
            for offset in range(0, len(data), self._ENTRY_SIZE)
        ]

    def header(self) -> dict:
        return self.__origin.header()  # pragma: no cover

    def data(self) -> bytes:
        return self.__origin.data()  # pragma: no cover

    def name(self) -> str:
        return self.__origin.name()  # pragma: no cover


class ValidatedSymbolTable(SymbolTable):
    def __init__(self, origin: SymbolTable):
        self.__origin = origin

    def symbols(self) -> list[Symbol]:
        return [ValidatedSymbol(symbol) for symbol in self.__origin.symbols()]

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
                RawStringTable(
                    RawSection(self.__raw_data, headers[e_shstrndx])
                ),
            )
            for header in headers
        ]

    def find(self, name: str) -> Section:
        for section in self.all():
            if section.name() == name:
                return section
        raise ValueError(f"Section '{name}' not found")  # pragma: no cover
