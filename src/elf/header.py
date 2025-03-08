import struct
from abc import ABC, abstractmethod


class ExecutableHeader(ABC):
    @abstractmethod
    def fields(self) -> dict:
        pass

    @abstractmethod
    def change(self, fields: dict) -> None:
        pass


class RawExecutableHeader(ExecutableHeader):
    __HEADER_SIZE = 64

    __READ_STRUCT_FORMAT = "<16sHHIQQQIHHHHHH"
    __WRITE_STRUCT_FORMAT = "<4sBBBBB7sHHIQQQIHHHHHH"

    __MAGIC_VALUE = b"\x7fELF"

    __ELFDATA2LSB = 1
    __ELFDATA2MSB = 2

    __ET_REL = 1
    __ET_EXEC = 2
    __ET_DYN = 3
    __ET_CORE = 4

    __ELFCLASS64 = 2

    __EM_X86_64 = 62

    __ENDIANNESS = [__ELFDATA2LSB, __ELFDATA2MSB]
    __TYPES = [
        __ET_REL,
        __ET_EXEC,
        __ET_DYN,
        __ET_CORE,
    ]

    def __init__(self, filename: str):
        self.__filename = filename

    def fields(self) -> dict:
        try:
            _struct = struct.unpack(
                self.__READ_STRUCT_FORMAT,
                self.__data(self.__filename)[
                    : struct.calcsize(self.__READ_STRUCT_FORMAT)
                ],
            )
        except struct.error:
            raise ValueError("Unable to process ELF file")
        return self.__valid_fields(
            {
                "e_ident": {
                    "EI_MAG": _struct[0][:4],
                    "EI_CLASS": _struct[0][4],
                    "EI_DATA": _struct[0][5],
                    "EI_VERSION": _struct[0][6],
                    "EI_OSABI": _struct[0][7],
                    "EI_ABIVERSION": _struct[0][8],
                    "EI_PAD": _struct[0][9:16],
                },
                "e_type": _struct[1],
                "e_machine": _struct[2],
                "e_version": _struct[3],
                "e_entry": _struct[4],
                "e_phoff": _struct[5],
                "e_shoff": _struct[6],
                "e_flags": _struct[7],
                "e_ehsize": _struct[8],
                "e_phentsize": _struct[9],
                "e_phnum": _struct[10],
                "e_shentsize": _struct[11],
                "e_shnum": _struct[12],
                "e_shstrndx": _struct[13],
            }
        )

    def change(self, fields: dict) -> None:
        try:
            _struct = struct.pack(
                self.__WRITE_STRUCT_FORMAT,
                *self.__changed_fields(fields, self.fields()),
            )
            self.__write_data(self.__filename, _struct)
        except struct.error:
            raise ValueError("Unable to process ELF file")

    def __data(self, filename: str) -> bytes:
        try:
            with open(filename, "rb") as file:
                return file.read(self.__HEADER_SIZE)
        except OSError:
            raise ValueError("Failed to read ELF file")

    def __valid_fields(self, fields: dict) -> dict:
        if not self.__are_fields_valid(fields):
            raise ValueError("ELF file is not valid")
        if not self.__is_64_bit(fields):
            raise ValueError("ELF file must be 64-bit")
        return fields

    def __are_fields_valid(self, fields: dict) -> bool:
        return (
            fields["e_ident"]["EI_MAG"] == self.__MAGIC_VALUE
            and fields["e_ident"]["EI_DATA"] in self.__ENDIANNESS
            and fields["e_ident"]["EI_VERSION"] == 1
            and fields["e_type"] in self.__TYPES
        )

    def __is_64_bit(self, fields: dict) -> bool:
        return (
            fields["e_ident"]["EI_CLASS"] == self.__ELFCLASS64
            and fields["e_machine"] == self.__EM_X86_64
        )

    def __changed_fields(self, new: dict, original: dict) -> tuple:
        return tuple(
            new.get("e_ident", {}).get(field, original["e_ident"][field])
            for field in [
                "EI_MAG",
                "EI_CLASS",
                "EI_DATA",
                "EI_VERSION",
                "EI_OSABI",
                "EI_ABIVERSION",
                "EI_PAD",
            ]
        ) + tuple(
            new.get(field, original[field])
            for field in [
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
        )

    def __write_data(self, filename: str, data: bytes):
        try:
            with open(filename, "r+b") as file:
                file.write(data)
        except OSError:
            raise ValueError("Failed to write to ELF file")
