import struct
from abc import ABC, abstractmethod
from typing import Any

from src.elf.executable_header import ExecutableHeader
from src.elf.validation import Validatable


class ProgramHeader(ABC):
    HEADER_SIZE = 56
    FIELDS = [
        "p_type",
        "p_flags",
        "p_offset",
        "p_vaddr",
        "p_paddr",
        "p_filesz",
        "p_memsz",
        "p_align",
    ]

    PT_NULL = 0
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_NOTE = 4
    PT_SHLIB = 5
    PT_PHDR = 6
    PT_TLS = 7

    PT_LOOS = 0x60000000
    PT_HIOS = 0x6FFFFFFF
    PT_LOPROC = 0x70000000
    PT_HIPROC = 0x7FFFFFFF

    PT_GNU_EH_FRAME = 0x6474E550
    PT_GNU_STACK = 0x6474E551
    PT_GNU_RELRO = 0x6474E552
    PT_GNU_PROPERTY = 0x6474E553

    PF_X = 0x1
    PF_W = 0x2
    PF_R = 0x4

    @abstractmethod
    def fields(self) -> dict[str, int]:
        pass  # pragma: no cover

    @abstractmethod
    def change(self, fields: dict[str, int]) -> None:
        pass  # pragma: no cover


class ProgramHeaders(ABC):
    @abstractmethod
    def all(self) -> list[ProgramHeader]:
        pass  # pragma: no cover


class RawProgramHeader(ProgramHeader):
    __STRUCT_FORMAT = "<IIQQQQQQ"

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
                            self.__offset : self.__offset + self.HEADER_SIZE
                        ],
                    ),
                )
            )
        except struct.error:
            raise ValueError("Unable to process data")

    def change(self, fields: dict[str, int]) -> None:
        try:
            self.__raw_data[
                self.__offset : self.__offset + self.HEADER_SIZE
            ] = struct.pack(
                self.__STRUCT_FORMAT,
                *(fields[field] for field in self.FIELDS),
            )
        except (KeyError, struct.error):
            raise ValueError("Unable to process data")


class RawProgramHeaders(ProgramHeaders):
    def __init__(
        self, raw_data: bytearray, executable_header: ExecutableHeader
    ):
        self.__raw_data = raw_data
        self.__executable_header = executable_header

    def all(self) -> list[ProgramHeader]:
        fields = self.__executable_header.fields()
        if self.__is_metadata_invalid(fields):
            raise ValueError(
                "Program header table metadata is missing or invalid"
            )
        return [
            RawProgramHeader(
                self.__raw_data,
                fields["e_phoff"] + index * fields["e_phentsize"],
            )
            for index in range(fields["e_phnum"])
        ]

    def __is_metadata_invalid(self, fields: dict[str, Any]) -> bool:
        return bool(
            fields["e_phoff"] == 0
            or fields["e_phnum"] == 0
            or fields["e_phentsize"] == 0
            or (
                fields["e_phoff"] + (fields["e_phentsize"] * fields["e_phnum"])
                > len(self.__raw_data)
            )
        )


class ValidatedProgramHeader(ProgramHeader, Validatable):
    def __init__(self, origin: ProgramHeader):
        self.__origin = origin

    def fields(self) -> dict[str, int]:
        return self.__origin.fields()

    def change(self, fields: dict[str, int]) -> None:
        self.__validate(fields)
        self.__origin.change(fields)

    def validate(self) -> None:
        self.__validate(self.__origin.fields())

    def __validate(self, fields: dict[str, int]) -> None:
        invalid_fields: dict[str, int] = {}
        for field, value in fields.items():
            match field:
                case "p_type":
                    if not self.__is_valid_type(value):
                        invalid_fields[field] = value
                case "p_flags":
                    if (
                        value == 0
                        or value & ~(self.PF_X | self.PF_W | self.PF_R) != 0
                    ):
                        invalid_fields[field] = value
                case "p_align":
                    if not self.__is_power_of_two(value) and value != 0:
                        invalid_fields[field] = value
                case (
                    "p_filesz" | "p_memsz" | "p_offset" | "p_vaddr" | "p_paddr"
                ):
                    if value < 0:
                        invalid_fields[field] = value
                case _:
                    if field not in self.FIELDS:  # pragma: no cover
                        invalid_fields[field] = value
        if invalid_fields:
            raise ValueError(
                self.error_message(
                    f"Program header (p_offset={fields['p_offset']})",
                    invalid_fields,
                )
            )

    def __is_valid_type(self, p_type: int) -> bool:
        return (
            p_type
            in [
                self.PT_NULL,
                self.PT_LOAD,
                self.PT_DYNAMIC,
                self.PT_INTERP,
                self.PT_NOTE,
                self.PT_SHLIB,
                self.PT_PHDR,
                self.PT_TLS,
            ]
            or (self.PT_LOOS <= p_type <= self.PT_HIOS)
            or (self.PT_LOPROC <= p_type <= self.PT_HIPROC)
        )

    def __is_power_of_two(self, value: int) -> bool:
        return (value & (value - 1)) == 0


class ValidatedProgramHeaders(ProgramHeaders, Validatable):
    def __init__(self, origin: ProgramHeaders):
        self.__origin = origin

    def all(self) -> list[ProgramHeader]:
        return [
            ValidatedProgramHeader(program_header)
            for program_header in self.__origin.all()
        ]

    def validate(self) -> None:
        for program_header in self.__origin.all():
            ValidatedProgramHeader(program_header).validate()
