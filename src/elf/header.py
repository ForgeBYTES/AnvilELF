import struct
from abc import ABC, abstractmethod


class Header(ABC):
    @abstractmethod
    def fields(self) -> dict:
        pass


class ExecutableHeader(Header):
    __MAGIC_VALUE = b"\x7fELF"
    __HEADER_SIZE = 64
    __STRUCT_FORMAT = "<16sHHIQQQIHHHHHH"

    def __init__(self, filename: str):
        self.__filename = filename

    def fields(self) -> dict:
        data = self.__data(self.__filename)
        struct_data = struct.unpack(
            self.__STRUCT_FORMAT,
            data[: struct.calcsize(self.__STRUCT_FORMAT)],
        )
        return {
            "e_ident": {
                "EI_MAG": struct_data[0][:4],
                "EI_CLASS": struct_data[0][4],
                "EI_DATA": struct_data[0][5],
                "EI_VERSION": struct_data[0][6],
                "EI_OSABI": struct_data[0][7],
                "EI_ABIVERSION": struct_data[0][8],
                "EI_PAD": struct_data[0][9:16],
            },
            "e_type": struct_data[1],
            "e_machine": struct_data[2],
            "e_version": struct_data[3],
            "e_entry": struct_data[4],
            "e_phoff": struct_data[5],
            "e_shoff": struct_data[6],
            "e_flags": struct_data[7],
            "e_ehsize": struct_data[8],
            "e_phentsize": struct_data[9],
            "e_phnum": struct_data[10],
            "e_shentsize": struct_data[11],
            "e_shnum": struct_data[12],
            "e_shstrndx": struct_data[13],
        }

    def __data(self, filename) -> bytes:
        try:
            with open(filename, "rb") as file:
                data = file.read(self.__HEADER_SIZE)
                self.__validate_data(data, filename)
                return data
        except OSError:
            raise ValueError(f"Could not open ELF binary '{filename}'")

    def __validate_data(self, data: bytes, filename: str) -> bytes:
        if not self.__is_valid_elf(data):
            raise ValueError(
                "The file '{}' is not a valid ELF binary".format(filename)
            )
        if not self.__is_64_bit(data):
            raise ValueError("ELF binary must be 64-bit")
        return data

    def __is_valid_elf(self, data: bytes) -> bool:
        return data[:4] == self.__MAGIC_VALUE

    def __is_64_bit(self, data: bytes) -> bool:
        return data[4] == 2
