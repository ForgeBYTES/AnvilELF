import struct
from abc import ABC, abstractmethod
from typing import Any

from src.elf.validation import Validatable


class ExecutableHeader(ABC):
    HEADER_SIZE = 64
    E_INDENT_FIELDS = [
        "ei_mag",
        "ei_class",
        "ei_data",
        "ei_version",
        "ei_osabi",
        "ei_abiversion",
        "ei_pad",
    ]
    FIELDS = [
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

    MAGIC_VALUE = b"\x7fELF"

    ELFDATA2LSB = 1
    ELFDATA2MSB = 2

    ET_REL = 1
    ET_EXEC = 2
    ET_DYN = 3
    ET_CORE = 4

    ELFCLASS64 = 2

    EM_X86_64 = 62

    ENDIANNESS = [ELFDATA2LSB, ELFDATA2MSB]
    TYPES = [ET_REL, ET_EXEC, ET_DYN, ET_CORE]

    @abstractmethod
    def fields(self) -> dict[str, Any]:
        pass  # pragma: no cover

    @abstractmethod
    def change(self, fields: dict[str, Any]) -> None:
        pass  # pragma: no cover


class RawExecutableHeader(ExecutableHeader):
    __STRUCT_FORMAT = "<4sBBBBB7sHHIQQQIHHHHHH"

    def __init__(self, raw_data: bytearray):
        self.__raw_data = raw_data

    def fields(self) -> dict[str, Any]:
        try:
            _struct = struct.unpack(
                self.__STRUCT_FORMAT, self.__raw_data[: self.HEADER_SIZE]
            )
        except struct.error:
            raise ValueError("Unable to process data")
        fields = {
            "e_ident": {
                "ei_mag": _struct[0],
                "ei_class": _struct[1],
                "ei_data": _struct[2],
                "ei_version": _struct[3],
                "ei_osabi": _struct[4],
                "ei_abiversion": _struct[5],
                "ei_pad": _struct[6],
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
        self.__assert_64_bit(fields)
        return fields

    def change(self, fields: dict[str, Any]) -> None:
        try:
            self.__raw_data[: self.HEADER_SIZE] = struct.pack(
                self.__STRUCT_FORMAT,
                *tuple(
                    fields["e_ident"][field] for field in self.E_INDENT_FIELDS
                ),
                *tuple(
                    fields[field]
                    for field in self.FIELDS
                    if field != "e_ident"
                ),
            )
        except (KeyError, struct.error):
            raise ValueError("Unable to process data")

    def __assert_64_bit(self, fields: dict[str, Any]) -> None:
        if not (
            fields["e_ident"]["ei_class"] == self.ELFCLASS64
            and fields["e_machine"] == self.EM_X86_64
            and fields["e_ehsize"] == self.HEADER_SIZE
        ):
            raise ValueError("Binary must be 64-bit")


class ValidatedExecutableHeader(ExecutableHeader, Validatable):
    def __init__(self, origin: ExecutableHeader):
        self.__origin = origin

    def fields(self) -> dict[str, Any]:
        return self.__origin.fields()

    def change(self, fields: dict[str, Any]) -> None:
        self.__validate(fields)
        return self.__origin.change(fields)

    def validate(self) -> None:
        self.__validate(self.__origin.fields())

    def __validate(self, fields: dict[str, Any]) -> None:
        invalid_fields: dict[str, Any] = {}
        for field, value in fields.items():
            match field:
                case "e_ident":
                    invalid_fields.update(self.__invalid_e_ident(value))
                case "e_type":
                    if value not in self.TYPES:
                        invalid_fields[field] = value
                case "e_machine":
                    if value != self.EM_X86_64:
                        invalid_fields[field] = value
                case "e_entry":
                    if value <= 0:
                        invalid_fields[field] = value
                case "e_phoff" | "e_shoff":
                    if not self.__is_aligned(value):
                        invalid_fields[field] = value
                case "e_ehsize":
                    if value != 64:
                        invalid_fields[field] = value
                case "e_shentsize":
                    if value not in [0, 64]:
                        invalid_fields[field] = value
                case "e_phentsize":
                    if value not in [0, 56]:
                        invalid_fields[field] = value
                case "e_flags":
                    if fields["e_machine"] == self.EM_X86_64 and value != 0:
                        invalid_fields[field] = value
                case _:
                    if field not in self.FIELDS:
                        invalid_fields[field] = value
        if invalid_fields:
            raise ValueError(
                self.error_message("Executable header", invalid_fields)
            )

    def __invalid_e_ident(self, fields: dict[str, Any]) -> dict[str, Any]:
        invalid_fields: dict[str, Any] = {}
        for field, value in fields.items():
            match field:
                case "ei_mag":
                    if value != self.MAGIC_VALUE:
                        invalid_fields[field] = value
                case "ei_class":
                    if value != ExecutableHeader.ELFCLASS64:
                        invalid_fields[field] = value
                case "ei_data":
                    if value not in self.ENDIANNESS:
                        invalid_fields[field] = value
                case "ei_version":
                    if value != 1:
                        invalid_fields[field] = value
                case _:
                    if field not in self.E_INDENT_FIELDS:
                        invalid_fields[field] = value
        return invalid_fields

    def __is_aligned(self, offset: int) -> bool:
        return offset >= 0 and offset % 8 == 0
