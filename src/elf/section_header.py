import struct
from abc import ABC, abstractmethod

from src.elf.executable_header import ExecutableHeader


class SectionHeader(ABC):
    _HEADER_SIZE = 64
    _FIELDS = [
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

    _SHT_NULL = 0
    _SHT_PROGBITS = 1
    _SHT_SYMTAB = 2
    _SHT_STRTAB = 3
    _SHT_RELA = 4
    _SHT_HASH = 5
    _SHT_DYNAMIC = 6
    _SHT_NOTE = 7
    _SHT_NOBITS = 8
    _SHT_REL = 9
    _SHT_SHLIB = 10
    _SHT_DYNSYM = 11
    _SHT_INIT_ARRAY = 14
    _SHT_FINI_ARRAY = 15
    _SHT_PREINIT_ARRAY = 16
    _SHT_GROUP = 17
    _SHT_SYMTAB_SHNDX = 18

    # fmt: off
    _TYPES = [
        _SHT_NULL, _SHT_PROGBITS, _SHT_SYMTAB, _SHT_STRTAB, _SHT_RELA,
        _SHT_HASH, _SHT_DYNAMIC, _SHT_NOTE, _SHT_NOBITS, _SHT_REL,
        _SHT_SHLIB, _SHT_DYNSYM, _SHT_INIT_ARRAY, _SHT_FINI_ARRAY,
        _SHT_PREINIT_ARRAY, _SHT_GROUP, _SHT_SYMTAB_SHNDX,
    ]
    # fmt: on

    _SHT_SUNW_MOVE = 0x6FFFFFFA
    _SHT_SUNW_COMDAT = 0x6FFFFFFB
    _SHT_SUNW_SYMINFO = 0x6FFFFFFC
    _SHT_SUNW_VERDEF = 0x6FFFFFFD
    _SHT_SUNW_VERNEED = 0x6FFFFFFE
    _SHT_SUNW_VERSYM = 0x6FFFFFFF

    _SHT_LOOS = 0x60000000
    _SHT_HIOS = 0x6FFFFFFF
    _SHT_LOPROC = 0x70000000
    _SHT_HIPROC = 0x7FFFFFFF
    _SHT_LOUSER = 0x80000000
    _SHT_HIUSER = 0x8FFFFFFF

    _SHF_WRITE = 0x1
    _SHF_ALLOC = 0x2
    _SHF_EXECINSTR = 0x4
    _SHF_MERGE = 0x10
    _SHF_STRINGS = 0x20
    _SHF_INFO_LINK = 0x40
    _SHF_LINK_ORDER = 0x80
    _SHF_OS_NONCONFORMING = 0x100
    _SHF_GROUP = 0x200
    _SHF_TLS = 0x400
    _SHF_MASKOS = 0x0FF00000
    _SHF_ORDERED = 0x40000000
    _SHF_EXCLUDE = 0x80000000
    _SHF_MASKPROC = 0xF0000000

    # fmt: off
    _FLAGS = (
        _SHF_WRITE | _SHF_ALLOC | _SHF_EXECINSTR | _SHF_MERGE |
        _SHF_STRINGS | _SHF_INFO_LINK | _SHF_LINK_ORDER |
        _SHF_OS_NONCONFORMING | _SHF_GROUP | _SHF_TLS | _SHF_MASKOS |
        _SHF_ORDERED | _SHF_EXCLUDE | _SHF_MASKPROC
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
                    self._FIELDS,
                    struct.unpack(
                        self.__STRUCT_FORMAT,
                        self.__raw_data[
                            self.__offset : self.__offset  # noqa: E203
                            + self._HEADER_SIZE
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
                *(fields[field] for field in self._FIELDS),
            )
            self.__raw_data[
                self.__offset : self.__offset + self._HEADER_SIZE  # noqa: E203
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
        return [
            RawSectionHeader(
                self.__raw_data,
                fields["e_shoff"] + index * fields["e_shentsize"],
            )
            for index in range(fields["e_shnum"])
        ]


class ValidatedSectionHeader(SectionHeader):
    def __init__(
        self,
        origin: SectionHeader,
        section_headers: SectionHeaders,
    ):
        self.__origin = origin
        self.__section_headers = section_headers

    def fields(self) -> dict[str, int]:
        fields = self.__origin.fields()
        self.__validate(fields, self.__section_headers)
        return fields

    def change(self, fields: dict[str, int]) -> None:
        self.__validate(fields, self.__section_headers)
        self.__origin.change(fields)

    def __validate(
        self,
        fields: dict[str, int],
        section_headers: SectionHeaders,
    ) -> None:
        for field, value in fields.items():
            match field:
                case "sh_type":
                    if self.__is_valid_type(value):
                        continue
                case "sh_flags":
                    if value & ~self._FLAGS == 0:
                        continue
                case "sh_addralign":
                    if self.__is_power_of_two(value):
                        continue
                case "sh_size" | "sh_offset":
                    if value >= 0:
                        continue
                case "sh_addr":
                    if self.__is_sh_addr_aligned(value, fields):
                        continue
                case "sh_link":
                    if self.__is_sh_link_valid(
                        value,
                        fields,
                        section_headers.all(),
                    ):
                        continue
                case "sh_info":
                    if self.__is_sh_info_valid(value, fields):
                        continue
                case "sh_entsize":
                    if self.__is_sh_entsize_valid(value, fields):
                        continue
                case _:
                    self.__validate_field_exists(field, self._FIELDS)
                    continue

            raise ValueError(f"Invalid value for {field}: {value}")

    def __is_valid_type(self, sh_type: int) -> bool:
        return (
            sh_type in self._TYPES
            or (self._SHT_LOOS <= sh_type <= self._SHT_HIOS)
            or (self._SHT_LOPROC <= sh_type <= self._SHT_HIPROC)
            or (self._SHT_LOUSER <= sh_type <= self._SHT_HIUSER)
        )

    def __is_power_of_two(self, value: int) -> bool:
        return (value & (value - 1)) == 0

    def __is_sh_addr_aligned(
        self, sh_addr: int, fields: dict[str, int]
    ) -> bool:
        if fields["sh_flags"] & self._SHF_ALLOC:
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
            self._SHT_DYNAMIC: [self._SHT_STRTAB],
            self._SHT_HASH: [self._SHT_DYNSYM],
            self._SHT_REL: [self._SHT_SYMTAB, self._SHT_DYNSYM],
            self._SHT_RELA: [self._SHT_SYMTAB, self._SHT_DYNSYM],
            self._SHT_SYMTAB: [self._SHT_STRTAB],
            self._SHT_DYNSYM: [self._SHT_STRTAB],
            self._SHT_GROUP: [self._SHT_SYMTAB, self._SHT_DYNSYM],
            self._SHT_SYMTAB_SHNDX: [self._SHT_SYMTAB],
            self._SHT_SUNW_COMDAT: [0],
            self._SHT_SUNW_SYMINFO: [self._SHT_DYNSYM],
            self._SHT_SUNW_VERDEF: [self._SHT_STRTAB],
            self._SHT_SUNW_VERNEED: [self._SHT_STRTAB],
            self._SHT_SUNW_VERSYM: [self._SHT_DYNSYM],
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
                self._SHT_DYNAMIC,
                self._SHT_HASH,
                self._SHT_SYMTAB_SHNDX,
                self._SHT_SUNW_MOVE,
                self._SHT_SUNW_COMDAT,
                self._SHT_SUNW_VERSYM,
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
                self._SHT_SYMTAB,
                self._SHT_DYNSYM,
                self._SHT_RELA,
                self._SHT_REL,
                self._SHT_DYNAMIC,
                self._SHT_HASH,
                self._SHT_SYMTAB_SHNDX,
                self._SHT_SUNW_SYMINFO,
                self._SHT_SUNW_VERSYM,
            ]
            else True
        )

    def __validate_field_exists(self, field: str, fields: list[str]) -> None:
        if field not in fields:
            raise ValueError(f"Unknown field {field}")


class ValidatedSectionHeaders(SectionHeaders):
    def __init__(self, origin: SectionHeaders):
        self.__origin = origin

    def all(self) -> list[SectionHeader]:
        return [
            ValidatedSectionHeader(section, self.__origin)
            for section in self.__origin.all()
        ]
