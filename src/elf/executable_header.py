import struct
from abc import ABC, abstractmethod


class ExecutableHeader(ABC):
    _HEADER_SIZE = 64

    _E_INDENT_FIELDS = [
        "EI_MAG",
        "EI_CLASS",
        "EI_DATA",
        "EI_VERSION",
        "EI_OSABI",
        "EI_ABIVERSION",
        "EI_PAD",
    ]
    _FIELDS = [
        "e_ident",
        "e_type",
        "e_machine",
        "e_version",
        "e_entry",
        "e_phoff",
        "e_shoff",
        "e_flags",
        "e_ehsize",
        "e_phentsize",
        "e_phnum",
        "e_shentsize",
        "e_shnum",
        "e_shstrndx",
    ]

    _MAGIC_VALUE = b"\x7fELF"

    _ELFDATA2LSB = 1
    _ELFDATA2MSB = 2

    _ET_REL = 1
    _ET_EXEC = 2
    _ET_DYN = 3
    _ET_CORE = 4

    _ELFCLASS64 = 2

    _EM_X86_64 = 62

    _ENDIANNESS = [_ELFDATA2LSB, _ELFDATA2MSB]
    _TYPES = [_ET_REL, _ET_EXEC, _ET_DYN, _ET_CORE]

    @abstractmethod
    def fields(self) -> dict:  # pragma: no cover
        pass

    @abstractmethod
    def change(self, fields: dict) -> None:  # pragma: no cover
        pass

    @abstractmethod
    def __str__(self) -> str:  # pragma: no cover
        pass


class RawExecutableHeader(ExecutableHeader):
    __STRUCT_FORMAT = "<4sBBBBB7sHHIQQQIHHHHHH"

    def __init__(self, raw_data: bytearray):
        self.__raw_data = raw_data

    def fields(self) -> dict:
        try:
            _struct = struct.unpack(
                self.__STRUCT_FORMAT, self.__raw_data[: self._HEADER_SIZE]
            )
        except struct.error:
            raise ValueError("Unable to process data")
        return {
            "e_ident": {
                "EI_MAG": _struct[0],
                "EI_CLASS": _struct[1],
                "EI_DATA": _struct[2],
                "EI_VERSION": _struct[3],
                "EI_OSABI": _struct[4],
                "EI_ABIVERSION": _struct[5],
                "EI_PAD": _struct[6],
            },
            "e_type": _struct[7],
            "e_machine": _struct[8],
            "e_version": _struct[9],
            "e_entry": _struct[10],
            "e_phoff": _struct[11],
            "e_shoff": _struct[12],
            "e_flags": _struct[13],
            "e_ehsize": _struct[14],
            "e_phentsize": _struct[15],
            "e_phnum": _struct[16],
            "e_shentsize": _struct[17],
            "e_shnum": _struct[18],
            "e_shstrndx": _struct[19],
        }

    def change(self, fields: dict) -> None:
        try:
            self.__raw_data[: self._HEADER_SIZE] = struct.pack(
                self.__STRUCT_FORMAT,
                *tuple(
                    fields["e_ident"][field] for field in self._E_INDENT_FIELDS
                ),
                *tuple(
                    fields[field]
                    for field in self._FIELDS
                    if field != "e_ident"
                ),
            )
        except (KeyError, struct.error):
            raise ValueError("Unable to process data")

    def __str__(self) -> str:
        fields = self.fields()
        magic = fields["e_ident"]["EI_MAG"].decode("ascii")
        return (
            "Executable Header:\n"
            f"  Magic: {magic}\n"
            f"  Class: {fields['e_ident']['EI_CLASS']}\n"
            f"  Data: {fields['e_ident']['EI_DATA']}\n"
            f"  Version: {fields['e_ident']['EI_VERSION']}\n"
            f"  OS/ABI: {fields['e_ident']['EI_OSABI']}\n"
            f"  ABI Version: {fields['e_ident']['EI_ABIVERSION']}\n"
            f"  Type: {fields['e_type']}\n"
            f"  Machine: {fields['e_machine']}\n"
            f"  Entry point: 0x{fields['e_entry']:x}\n"
            f"  Start of section headers: {fields['e_shoff']}\n"
            f"  Number of section headers: {fields['e_shnum']}\n"
        )


class ValidatedExecutableHeader(ExecutableHeader):
    def __init__(self, origin: ExecutableHeader):
        self.__origin = origin

    def fields(self) -> dict:
        fields = self.__origin.fields()
        self.__validate_all(fields)
        return fields

    def change(self, fields: dict) -> None:
        self.__validate(fields)
        return self.__origin.change(fields)

    def __str__(self) -> str:
        return self.__origin.__str__()

    def __validate_all(self, fields: dict) -> None:
        if not self.__is_64_bit(fields):
            raise ValueError("Binary must be 64-bit")
        self.__validate(fields)

    def __is_64_bit(self, fields: dict) -> bool:
        return (
            fields["e_ident"]["EI_CLASS"] == self._ELFCLASS64
            and fields["e_machine"] == self._EM_X86_64
            and fields["e_ehsize"] == self._HEADER_SIZE
        )

    def __validate(self, fields: dict) -> None:
        for field, value in fields.items():
            match field:
                case "e_ident":
                    self.__validate_e_ident(value)
                    continue
                case "e_type":
                    if value in self._TYPES:
                        continue
                case "e_entry":
                    if value > 0:
                        continue
                case "e_phoff" | "e_shoff":
                    if self.__is_aligned(value):
                        continue
                case "e_ehsize":
                    if value == 64:
                        continue
                case "e_shentsize":
                    if value in [0, 64]:
                        continue
                case "e_phentsize":
                    if value in [0, 56]:
                        continue
                case "e_flags":
                    self.__validate_e_flags(value, fields)
                    continue
                case _:
                    self.__validate_field_exists(field, self._FIELDS)
                    continue
            raise ValueError(f"Invalid value for {field}")

    def __validate_e_ident(self, fields: dict):
        for field, value in fields.items():
            match field:
                case "EI_MAG":
                    if value == self._MAGIC_VALUE:
                        continue
                case "EI_DATA":
                    if value in self._ENDIANNESS:
                        continue
                case "EI_VERSION":
                    if value == 1:
                        continue
                case _:
                    self.__validate_field_exists(field, self._E_INDENT_FIELDS)
                    continue
            raise ValueError(f"Invalid value for {field}")

    def __is_aligned(self, offset: int) -> bool:
        return offset >= 0 and offset % 8 == 0

    def __validate_e_flags(self, e_flags: int, fields: dict) -> None:
        if fields["e_machine"] == self._EM_X86_64 and e_flags != 0:
            raise ValueError("Nonzero e_flags unexpected for x86-64")

    def __validate_field_exists(self, field: str, fields: list):
        if field not in fields:
            raise ValueError(f"Unknown field {field}")
