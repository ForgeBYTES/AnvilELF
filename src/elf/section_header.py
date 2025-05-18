import struct
from abc import ABC, abstractmethod
from typing import Any

from src.elf.executable_header import ExecutableHeader
from src.elf.validation import Validatable


class SectionHeader(ABC):
    HEADER_SIZE = 64
    FIELDS = [
        "sh_name",
        "sh_type",
        "sh_flags",
        "sh_addr",
        "sh_offset",
        "sh_size",
        "sh_link",
        "sh_info",
        "sh_addralign",
        "sh_entsize",
    ]

    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_HASH = 5
    SHT_DYNAMIC = 6
    SHT_NOTE = 7
    SHT_NOBITS = 8
    SHT_REL = 9
    SHT_SHLIB = 10
    SHT_DYNSYM = 11
    SHT_INIT_ARRAY = 14
    SHT_FINI_ARRAY = 15
    SHT_PREINIT_ARRAY = 16
    SHT_GROUP = 17
    SHT_SYMTAB_SHNDX = 18

    # fmt: off
    _TYPES = [
        SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA,
        SHT_HASH, SHT_DYNAMIC, SHT_NOTE, SHT_NOBITS, SHT_REL,
        SHT_SHLIB, SHT_DYNSYM, SHT_INIT_ARRAY, SHT_FINI_ARRAY,
        SHT_PREINIT_ARRAY, SHT_GROUP, SHT_SYMTAB_SHNDX,
    ]
    # fmt: on

    SHT_SUNW_MOVE = 0x6FFFFFFA
    SHT_SUNW_COMDAT = 0x6FFFFFFB
    SHT_SUNW_SYMINFO = 0x6FFFFFFC
    SHT_SUNW_VERDEF = 0x6FFFFFFD
    SHT_SUNW_VERNEED = 0x6FFFFFFE
    SHT_SUNW_VERSYM = 0x6FFFFFFF

    SHT_LOOS = 0x60000000
    SHT_HIOS = 0x6FFFFFFF
    SHT_LOPROC = 0x70000000
    SHT_HIPROC = 0x7FFFFFFF
    SHT_LOUSER = 0x80000000
    SHT_HIUSER = 0x8FFFFFFF

    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4
    SHF_MERGE = 0x10
    SHF_STRINGS = 0x20
    SHF_INFO_LINK = 0x40
    SHF_LINK_ORDER = 0x80
    SHF_OS_NONCONFORMING = 0x100
    SHF_GROUP = 0x200
    SHF_TLS = 0x400
    SHF_MASKOS = 0x0FF00000
    SHF_ORDERED = 0x40000000
    SHF_EXCLUDE = 0x80000000
    SHF_MASKPROC = 0xF0000000

    # fmt: off
    FLAGS = (
        SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR | SHF_MERGE |
        SHF_STRINGS | SHF_INFO_LINK | SHF_LINK_ORDER |
        SHF_OS_NONCONFORMING | SHF_GROUP | SHF_TLS | SHF_MASKOS |
        SHF_ORDERED | SHF_EXCLUDE | SHF_MASKPROC
    )
    # fmt: on

    @abstractmethod
    def fields(self) -> dict[str, int]:
        pass  # pragma: no cover

    @abstractmethod
    def change(self, fields: dict[str, int]) -> None:
        pass  # pragma: no cover


class SectionHeaders(ABC):
    _HEADER_SIZE = 64

    @abstractmethod
    def all(self) -> list[SectionHeader]:
        pass  # pragma: no cover


class RawSectionHeader(SectionHeader):
    __STRUCT_FORMAT = "<IIQQQQIIQQ"

    def __init__(self, raw_data: bytearray, offset: int):
        self.__raw_data = raw_data
        self.__offset = offset

    def fields(self) -> dict[str, int]:
        try:
            return dict(
                zip(
                    self.FIELDS,
                    struct.unpack(
                        self.__STRUCT_FORMAT,
                        self.__raw_data[
                            self.__offset : self.__offset  # noqa: E203
                            + self.HEADER_SIZE
                        ],
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
                self.__offset : self.__offset + self.HEADER_SIZE  # noqa: E203
            ] = _struct
        except (KeyError, struct.error):
            raise ValueError("Unable to process data")


class RawSectionHeaders(SectionHeaders):
    def __init__(
        self, raw_data: bytearray, executable_header: ExecutableHeader
    ):
        self.__raw_data = raw_data
        self.__executable_header = executable_header

    def all(self) -> list[SectionHeader]:
        fields = self.__executable_header.fields()
        if self.__is_metadata_invalid(fields):
            raise ValueError(
                "Section header table metadata is missing or invalid"
            )
        return [
            RawSectionHeader(
                self.__raw_data,
                fields["e_shoff"] + index * fields["e_shentsize"],
            )
            for index in range(fields["e_shnum"])
        ]

    def __is_metadata_invalid(self, fields: dict[str, Any]) -> bool:
        return bool(
            fields["e_shoff"] == 0
            or fields["e_shnum"] == 0
            or fields["e_shentsize"] == 0
            or (
                fields["e_shoff"] + (fields["e_shentsize"] * fields["e_shnum"])
                > len(self.__raw_data)
            )
        )


class ValidatedSectionHeader(SectionHeader, Validatable):
    def __init__(
        self,
        origin: SectionHeader,
        section_headers: SectionHeaders,
    ):
        self.__origin = origin
        self.__section_headers = section_headers

    def fields(self) -> dict[str, int]:
        return self.__origin.fields()

    def change(self, fields: dict[str, int]) -> None:
        self.__validate(fields, self.__section_headers)
        self.__origin.change(fields)

    def validate(self) -> None:
        self.__validate(self.__origin.fields(), self.__section_headers)

    def __validate(
        self,
        fields: dict[str, int],
        section_headers: SectionHeaders,
    ) -> None:
        invalid_fields: dict[str, int] = {}
        for field, value in fields.items():
            match field:
                case "sh_type":
                    if not self.__is_valid_type(value):
                        invalid_fields[field] = value
                case "sh_flags":
                    if value & ~self.FLAGS != 0:
                        invalid_fields[field] = value
                case "sh_addralign":
                    if not self.__is_power_of_two(value):
                        invalid_fields[field] = value
                case "sh_size" | "sh_offset":
                    if value < 0:
                        invalid_fields[field] = value
                case "sh_addr":
                    if not self.__is_sh_addr_aligned(value, fields):
                        invalid_fields[field] = value
                case "sh_link":
                    if not self.__is_sh_link_valid(
                        value, fields, section_headers.all()
                    ):
                        invalid_fields[field] = value
                case "sh_info":
                    if not self.__is_sh_info_valid(value, fields):
                        invalid_fields[field] = value
                case "sh_entsize":
                    if not self.__is_sh_entsize_valid(value, fields):
                        invalid_fields[field] = value
                case _:
                    if field not in self.FIELDS:
                        invalid_fields[field] = value
        if invalid_fields:
            raise ValueError(
                self.error_message(
                    f"Section header ({fields['sh_name']})",
                    invalid_fields,
                )
            )

    def __is_valid_type(self, sh_type: int) -> bool:
        return (
            sh_type in self._TYPES
            or (self.SHT_LOOS <= sh_type <= self.SHT_HIOS)
            or (self.SHT_LOPROC <= sh_type <= self.SHT_HIPROC)
            or (self.SHT_LOUSER <= sh_type <= self.SHT_HIUSER)
        )

    def __is_power_of_two(self, value: int) -> bool:
        return (value & (value - 1)) == 0

    def __is_sh_addr_aligned(
        self, sh_addr: int, fields: dict[str, int]
    ) -> bool:
        if fields["sh_flags"] & self.SHF_ALLOC:
            return (
                sh_addr % fields["sh_addralign"] == 0
                if fields["sh_addralign"] not in [0, 1]
                else True
            )
        return True

    def __is_sh_link_valid(
        self,
        index: int,
        fields: dict[str, int],
        section_headers: list[SectionHeader],
    ) -> bool:
        links = {
            self.SHT_DYNAMIC: [self.SHT_STRTAB],
            self.SHT_HASH: [self.SHT_DYNSYM],
            self.SHT_REL: [self.SHT_SYMTAB, self.SHT_DYNSYM],
            self.SHT_RELA: [self.SHT_SYMTAB, self.SHT_DYNSYM],
            self.SHT_SYMTAB: [self.SHT_STRTAB],
            self.SHT_DYNSYM: [self.SHT_STRTAB],
            self.SHT_GROUP: [self.SHT_SYMTAB, self.SHT_DYNSYM],
            self.SHT_SYMTAB_SHNDX: [self.SHT_SYMTAB],
            self.SHT_SUNW_COMDAT: [0],
            self.SHT_SUNW_SYMINFO: [self.SHT_DYNSYM],
            self.SHT_SUNW_VERDEF: [self.SHT_STRTAB],
            self.SHT_SUNW_VERNEED: [self.SHT_STRTAB],
            self.SHT_SUNW_VERSYM: [self.SHT_DYNSYM],
        }
        if index < 0 or index >= len(section_headers):
            return False
        if types := links.get(fields["sh_type"]):
            return section_headers[index].fields()["sh_type"] in types
        return True

    def __is_sh_info_valid(
        self,
        value: int,
        fields: dict[str, int],
    ) -> bool:
        return (
            value == 0
            if fields["sh_type"]
            in [
                self.SHT_DYNAMIC,
                self.SHT_HASH,
                self.SHT_SYMTAB_SHNDX,
                self.SHT_SUNW_MOVE,
                self.SHT_SUNW_COMDAT,
                self.SHT_SUNW_VERSYM,
            ]
            else True
        )

    def __is_sh_entsize_valid(
        self,
        value: int,
        fields: dict[str, int],
    ) -> bool:
        return (
            value > 0
            if fields["sh_type"]
            in [
                self.SHT_SYMTAB,
                self.SHT_DYNSYM,
                self.SHT_RELA,
                self.SHT_REL,
                self.SHT_DYNAMIC,
                self.SHT_HASH,
                self.SHT_SYMTAB_SHNDX,
                self.SHT_SUNW_SYMINFO,
                self.SHT_SUNW_VERSYM,
            ]
            else True
        )


class ValidatedSectionHeaders(SectionHeaders, Validatable):
    def __init__(self, origin: SectionHeaders):
        self.__origin = origin

    def all(self) -> list[SectionHeader]:
        return [
            ValidatedSectionHeader(section_header, self.__origin)
            for section_header in self.__origin.all()
        ]

    def validate(self) -> None:
        for section_header in self.all():
            ValidatedSectionHeader(section_header, self.__origin).validate()
