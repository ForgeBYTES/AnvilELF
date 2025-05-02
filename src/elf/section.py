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
    def name_by_offset(self, offset: int) -> str:
        pass  # pragma: no cover


class Disassembly(ABC):
    @abstractmethod
    def instructions(self) -> list[str]:
        pass  # pragma: no cover


class Symbol(ABC):
    ENTRY_SIZE = 24

    FIELDS = [
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
    BINDS = [
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
    TYPES = [
        STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_SECTION, STT_FILE,
        STT_COMMON, STT_TLS, STT_LOOS, STT_HIOS, STT_LOPROC,
        STT_HIPROC,
    ]
    # fmt: on

    STV_DEFAULT = 0
    STV_INTERNAL = 1
    STV_HIDDEN = 2
    STV_PROTECTED = 3

    VISIBILITIES = [
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
        if self.__is_in_range(fields):
            return memoryview(self.__raw_data)[
                fields["sh_offset"] : fields["sh_offset"]  # noqa: E203
                + fields["sh_size"]
            ]
        raise ValueError("Exceeded section size")

    def replace(self, data: bytes) -> None:
        fields = self.__section_header.fields()
        if not (
            self.__is_in_range(fields) and self.__is_valid_size(data, fields)
        ):
            raise ValueError("Invalid section size")
        self.__raw_data[
            fields["sh_offset"] : fields["sh_offset"]  # noqa: E203
            + fields["sh_size"]
        ] = data

    def name(self) -> str:
        if self.__shstrtab is not None:
            return self.__shstrtab.name_by_offset(
                self.__section_header.fields()["sh_name"]
            )
        return str(self.__section_header.fields()["sh_name"])

    def __is_in_range(self, fields: dict[str, int]) -> bool:
        return fields["sh_offset"] + fields["sh_size"] <= len(self.__raw_data)

    def __is_valid_size(self, data: bytes, fields: dict[str, int]) -> bool:
        return len(data) == fields["sh_size"]


class RawStringTable(StringTable):
    def __init__(self, origin: Section):
        self.__origin = origin

    def name_by_offset(self, offset: int) -> str:
        data = self.__origin.raw_data().tobytes()
        return self.__name_or_fallback(
            data, offset, data.find(b"\x00", offset)
        )

    def __name_or_fallback(self, data: bytes, offset: int, end: int) -> str:
        if self.__is_in_range(offset, end, data):
            return data[offset:end].decode("ascii", errors="replace")
        return str(offset)

    def __is_in_range(self, offset: int, end: int, data: bytes) -> bool:
        return 0 <= offset < len(data) and end != -1


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
                self.__shstrtab(e_shstrndx, headers),
            )
            for header in headers
        ]

    def find(self, name: str) -> Section:
        for section in self.all():
            if section.name() == name:
                return section
        raise ValueError(f"Section '{name}' not found")  # pragma: no cover

    def __shstrtab(
        self, index: int, headers: list[SectionHeader]
    ) -> StringTable | None:
        if (
            0 < index < len(headers)
            and headers[index].fields()["sh_type"] == SectionHeader.SHT_STRTAB
        ):
            return RawStringTable(RawSection(self.__raw_data, headers[index]))
        return None


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
                    self.FIELDS,
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
                *(fields[field] for field in self.FIELDS),
            )
            self.__raw_data[
                self.__offset : self.__offset + self.ENTRY_SIZE  # noqa: E203
            ] = _struct
        except (KeyError, struct.error):
            raise ValueError("Unable to process data")

    def name(self) -> str:
        return self.__string_table.name_by_offset(self.fields()["st_name"])

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
        invalid_fields: list[str] = []
        for field, value in fields.items():
            match field:
                case "st_info":
                    _type = value & 0xF
                    bind = value >> 4
                    if bind not in self.BINDS or _type not in self.TYPES:
                        invalid_fields.append(field)
                case "st_shndx":
                    if not (0 <= value <= 0xFFFF):
                        invalid_fields.append(field)
                case _:
                    if field not in self.FIELDS:
                        invalid_fields.append(field)
        if invalid_fields:
            raise ValueError(
                f"Symbol ({self.name()}) contains "
                f"invalid fields: {', '.join(invalid_fields)}"
            )


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
