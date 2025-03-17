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
    def fields(self) -> dict:  # pragma: no cover
        pass

    @abstractmethod
    def change(self, fields: dict) -> None:  # pragma: no cover
        pass


class SectionHeaders(ABC):
    _HEADER_SIZE = 64

    @abstractmethod
    def all(self) -> list[SectionHeader]:  # pragma: no cover
        pass


class RawSectionHeader(SectionHeader):
    __STRUCT_FORMAT = "<IIQQQQIIQQ"

    def __init__(
        self,
        offset: int | None = None,
        filename: str | None = None,
        raw_data: bytes | None = None,
    ):
        self.__offset = offset
        self.__filename = filename
        self.__raw_data = raw_data

    def fields(self) -> dict:
        try:
            return dict(
                zip(
                    self._FIELDS,
                    struct.unpack(self.__STRUCT_FORMAT, self.__data()),
                )
            )
        except struct.error:
            raise ValueError("Unable to process binary")

    def change(self, fields: dict) -> None:
        if self.__filename is None or self.__offset is None:
            raise ValueError("Filename and offset must be provided")

        original_fields = self.fields()
        self.__write_data(
            self.__filename,
            self.__offset,
            struct.pack(
                self.__STRUCT_FORMAT,
                *(
                    tuple(
                        fields.get(field, original_fields[field])
                        for field in self._FIELDS
                    )
                ),
            ),
        )

    def __data(self) -> bytes:
        if self.__raw_data is not None:
            return self.__raw_data

        if self.__filename is None or self.__offset is None:
            raise ValueError("Filename and offset must be provided")

        try:
            with open(self.__filename, "rb") as file:
                file.seek(self.__offset)
                return file.read(self._HEADER_SIZE)
        except OSError:
            raise ValueError("Failed to read file")

    def __write_data(self, filename: str, offset: int, data: bytes) -> None:
        try:
            with open(filename, "r+b") as file:
                file.seek(offset)
                file.write(data)
        except OSError:
            raise ValueError("Failed to write to file")


class RawSectionHeaders(SectionHeaders):
    def __init__(self, executable_header: ExecutableHeader):
        self.__executable_header = executable_header

    def all(self) -> list[SectionHeader]:
        fields = self.__executable_header.fields()
        data = self.__data(
            self.__executable_header.filename(),
            fields["e_shoff"],
            fields["e_shnum"],
            fields["e_shentsize"],
        )

        return [
            self.__header(data, index, fields["e_shentsize"])
            for index in range(fields["e_shnum"])
        ]

    def __header(self, data: bytes, index: int, size: int) -> SectionHeader:
        return RawSectionHeader(
            raw_data=data[index * size : (index + 1) * size]  # noqa: E203
        )

    def __data(
        self, filename: str, offset: int, count: int, size: int
    ) -> bytes:
        with open(filename, "rb") as file:
            file.seek(offset)
            return file.read(count * size)


class ValidatedSectionHeader(SectionHeader):
    def __init__(self, origin: SectionHeader):
        self.__origin = origin

    def fields(self) -> dict:
        fields = self.__origin.fields()
        self.__validate(fields)
        return fields

    def change(self, fields: dict) -> None:
        self.__validate(fields)
        self.__origin.change(fields)

    def __validate(self, fields: dict) -> None:
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

    def __is_sh_addr_aligned(self, sh_addr: int, fields: dict) -> bool:
        fields = (
            self.__origin.fields()
            if ("sh_flags" not in fields or "sh_addralign" not in fields)
            else fields
        )
        if fields["sh_flags"] & self._SHF_ALLOC:
            return (
                sh_addr % fields["sh_addralign"] == 0
                if fields["sh_addralign"] not in [0, 1]
                else True
            )
        return True

    def __validate_field_exists(self, field: str, fields: list):
        if field not in fields:
            raise ValueError(f"Unknown field {field}")


class ValidatedSectionHeaders(SectionHeaders):
    def __init__(self, origin: SectionHeaders):
        self.__origin = origin

    def all(self) -> list[SectionHeader]:
        return [
            ValidatedSectionHeader(section) for section in self.__origin.all()
        ]
