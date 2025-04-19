import struct
from abc import ABC, abstractmethod

import capstone

from src.elf.executable_header import ExecutableHeader
from src.elf.section_header import SectionHeader, SectionHeaders


class Section(ABC):
    @abstractmethod
    def header(self) -> dict[str, int]:
        pass  # pragma: no cover

    @abstractmethod
    def raw_data(self) -> memoryview:
        pass  # pragma: no cover

    @abstractmethod
    def replace(self, data: bytes) -> None:
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


class StringTable(ABC):
    @abstractmethod
    def name_by_index(self, sh_name: int) -> str:
        pass  # pragma: no cover


class Disassembly(ABC):
    @abstractmethod
    def instructions(self) -> list[str]:
        pass  # pragma: no cover


class Symbol(ABC):
    _ENTRY_SIZE = 24

    _FIELDS = [
        "st_name",
        "st_info",
        "st_other",
        "st_shndx",
        "st_value",
        "st_size",
    ]

    STB_LOCAL = 0
    STB_GLOBAL = 1
    STB_WEAK = 2
    STB_LOOS = 10
    STB_HIOS = 12
    STB_LOPROC = 13
    STB_HIPROC = 15

    # fmt: off
    _BINDS = [
        STB_LOCAL, STB_GLOBAL, STB_WEAK, STB_LOOS,
        STB_HIOS, STB_LOPROC, STB_HIPROC,
    ]
    # fmt: on

    STT_NOTYPE = 0
    STT_OBJECT = 1
    STT_FUNC = 2
    STT_SECTION = 3
    STT_FILE = 4
    STT_COMMON = 5
    STT_TLS = 6
    STT_LOOS = 10
    STT_HIOS = 12
    STT_LOPROC = 13
    STT_HIPROC = 15

    # fmt: off
    _TYPES = [
        STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_SECTION, STT_FILE,
        STT_COMMON, STT_TLS, STT_LOOS, STT_HIOS, STT_LOPROC,
        STT_HIPROC,
    ]
    # fmt: on

    STV_DEFAULT = 0
    STV_INTERNAL = 1
    STV_HIDDEN = 2
    STV_PROTECTED = 3

    _VISIBILITIES = [
        STV_DEFAULT,
        STV_INTERNAL,
        STV_HIDDEN,
        STV_PROTECTED,
    ]

    @abstractmethod
    def fields(self) -> dict[str, int]:
        pass  # pragma: no cover

    @abstractmethod
    def change(self, fields: dict[str, int]) -> None:
        pass  # pragma: no cover

    @abstractmethod
    def name(self) -> str:
        pass  # pragma: no cover

    @abstractmethod
    def bind(self) -> int:
        pass  # pragma: no cover

    @abstractmethod
    def type(self) -> int:
        pass  # pragma: no cover

    @abstractmethod
    def visibility(self) -> int:
        pass  # pragma: no cover


class SymbolTable(ABC):
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

    def header(self) -> dict[str, int]:
        return self.__section_header.fields()

    def raw_data(self) -> memoryview:
        fields = self.__section_header.fields()
        return memoryview(self.__raw_data)[
            fields["sh_offset"] : fields["sh_offset"]  # noqa: E203
            + fields["sh_size"]
        ]

    def replace(self, data: bytes) -> None:
        fields = self.__section_header.fields()
        self.__validate_size(data, fields)
        self.__raw_data[
            fields["sh_offset"] : fields["sh_offset"]  # noqa: E203
            + fields["sh_size"]
        ] = data

    def name(self) -> str:
        return (
            str(self.__section_header.fields()["sh_name"])
            if self.__shstrtab is None
            else self.__shstrtab.name_by_index(
                self.__section_header.fields()["sh_name"]
            )
        )

    def __validate_size(self, data: bytes, fields: dict[str, int]) -> None:
        if len(data) != fields["sh_size"]:
            raise ValueError("Invalid section size")


class RawStringTable(StringTable):
    def __init__(self, origin: Section):
        self.__origin = origin

    def name_by_index(self, sh_name: int) -> str:
        data = self.__origin.raw_data().tobytes()
        return data[
            sh_name : data.find(b"\x00", sh_name)  # noqa: E203
        ].decode("ascii")


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


class RawSymbol(Symbol):
    __STRUCT_FORMAT = "<IBBHQQ"

    def __init__(
        self, raw_data: memoryview, offset: int, string_table: StringTable
    ):
        self.__raw_data = raw_data
        self.__offset = offset
        self.__string_table = string_table

    def fields(self) -> dict[str, int]:
        try:
            return dict(
                zip(
                    self._FIELDS,
                    struct.unpack_from(
                        self.__STRUCT_FORMAT,
                        self.__raw_data,
                        self.__offset,
                    ),
                )
            )
        except struct.error:
            raise ValueError("Unable to process data")

    def change(self, fields: dict[str, int]) -> None:
        try:
            _struct = struct.pack(
                self.__STRUCT_FORMAT,
                *(fields[field] for field in self._FIELDS),
            )
            self.__raw_data[
                self.__offset : self.__offset + self._ENTRY_SIZE  # noqa: E203
            ] = _struct
        except (KeyError, struct.error):
            raise ValueError("Unable to process data")

    def name(self) -> str:
        return self.__string_table.name_by_index(self.fields()["st_name"])

    def bind(self) -> int:
        return int(self.fields()["st_info"] >> 4)

    def type(self) -> int:
        return int(self.fields()["st_info"] & 0xF)

    def visibility(self) -> int:
        return int(self.fields()["st_other"] & 0x3)


class ValidatedSymbol(Symbol):
    def __init__(self, origin: Symbol):
        self.__origin = origin

    def fields(self) -> dict[str, int]:
        fields = self.__origin.fields()
        self.__validate(fields)
        return fields

    def change(self, fields: dict[str, int]) -> None:
        self.__validate(fields)
        return self.__origin.change(fields)

    def name(self) -> str:
        return self.__origin.name()

    def bind(self) -> int:
        return self.__origin.bind()

    def type(self) -> int:
        return self.__origin.type()

    def visibility(self) -> int:
        return self.__origin.visibility()

    def __validate(self, fields: dict[str, int]) -> None:
        for field, value in fields.items():
            match field:
                case "st_info":
                    _type = value & 0xF
                    bind = value >> 4
                    if bind in self._BINDS and _type in self._TYPES:
                        continue
                case "st_shndx":
                    if 0 <= value <= 0xFFFF:
                        continue
                case _:
                    self.__validate_field_exists(field, self._FIELDS)
                    continue

            raise ValueError(f"Invalid value for {field}")

    def __validate_field_exists(self, field: str, fields: list[str]) -> None:
        if field not in fields:
            raise ValueError(f"Unknown field {field}")


class RawSymbolTable(SymbolTable):
    def __init__(self, section: Section, string_table: StringTable):
        self.__section = section
        self.__string_table = string_table

    def symbols(self) -> list[Symbol]:
        data = self.__section.raw_data()
        return [
            RawSymbol(data, offset, self.__string_table)
            for offset in range(0, len(data), self._ENTRY_SIZE)
        ]


class ValidatedSymbolTable(SymbolTable):
    def __init__(self, origin: SymbolTable):
        self.__origin = origin

    def symbols(self) -> list[Symbol]:
        return [ValidatedSymbol(symbol) for symbol in self.__origin.symbols()]


class RawDisassembly(Disassembly):
    __SHF_EXECINSTR = 0x4

    def __init__(self, section: Section):
        self.__section = section
        self.__cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def instructions(self) -> list[str]:
        header = self.__section.header()
        if self.__is_executable(header):
            self.__cs.syntax = capstone.CS_OPT_SYNTAX_INTEL
            return [
                self.__instruction(
                    instruction.address,
                    instruction.mnemonic,
                    instruction.op_str,
                )
                for instruction in self.__cs.disasm(
                    self.__section.raw_data(),
                    header["sh_addr"],
                )
            ]
        raise ValueError("Section is not executable")

    def __is_executable(self, header: dict[str, int]) -> bool:
        return bool(header["sh_flags"] & self.__SHF_EXECINSTR)

    def __instruction(self, address: str, mnemonic: str, op: str) -> str:
        return f"{address:08x}: {mnemonic} {op}".rstrip()
