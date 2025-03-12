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

    @abstractmethod
    def fields(self) -> dict:
        pass

    @abstractmethod
    def change(self, fields: dict) -> None:
        pass


class RawExecutableHeader(ExecutableHeader):
    __READ_STRUCT_FORMAT = "<16sHHIQQQIHHHHHH"
    __WRITE_STRUCT_FORMAT = "<4sBBBBB7sHHIQQQIHHHHHH"

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
            raise ValueError("Unable to process binary")
        return {
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

    def change(self, fields: dict) -> None:
        try:
            original_fields = self.fields()
            _struct = struct.pack(
                self.__WRITE_STRUCT_FORMAT,
                *(
                    tuple(
                        fields.get("e_ident", {}).get(
                            field,
                            original_fields["e_ident"][field],
                        )
                        for field in self._E_INDENT_FIELDS
                    )
                    + tuple(
                        fields.get(field, original_fields[field])
                        for field in self._FIELDS
                        if field != "e_ident"
                    )
                ),
            )
            self.__write_data(self.__filename, _struct)
        except struct.error:
            raise ValueError("Unable to process binary")

    def __data(self, filename: str) -> bytes:
        try:
            with open(filename, "rb") as file:
                return file.read(self._HEADER_SIZE)
        except OSError:
            raise ValueError("Failed to read file")

    def __write_data(self, filename: str, data: bytes):
        try:
            with open(filename, "r+b") as file:
                file.write(data)
        except OSError:
            raise ValueError("Failed to write to file")


class ValidatedExecutableHeader(ExecutableHeader):
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
    __TYPES = [__ET_REL, __ET_EXEC, __ET_DYN, __ET_CORE]

    def __init__(self, executable_header: ExecutableHeader):
        self.__executable_header = executable_header

    def fields(self) -> dict:
        fields = self.__executable_header.fields()

        self.__validate_all(fields)

        return fields

    def change(self, fields: dict) -> None:
        self.__validate(fields)

        return self.__executable_header.change(fields)

    def __validate_all(self, fields: dict) -> None:
        if not self.__is_valid_structure(fields):
            raise ValueError("Binary structure is not valid")
        if not self.__is_64_bit(fields):
            raise ValueError("Binary must be 64-bit")

        self.__validate(fields)

    def __is_valid_structure(self, fields: dict) -> bool:
        return (
            list(fields.keys()) == self._FIELDS
            and list(fields["e_ident"].keys()) == self._E_INDENT_FIELDS
        )

    def __is_64_bit(self, fields: dict) -> bool:
        return (
            fields["e_ident"]["EI_CLASS"] == self.__ELFCLASS64
            and fields["e_machine"] == self.__EM_X86_64
            and fields["e_ehsize"] == self._HEADER_SIZE
        )

    def __validate(self, fields: dict) -> None:
        for field, value in fields.items():
            match field:
                case "e_ident":
                    self.__validate_e_ident(value)
                    continue
                case "e_type":
                    if value in self.__TYPES:
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
                    if value == self.__MAGIC_VALUE:
                        continue
                case "EI_DATA":
                    if value in self.__ENDIANNESS:
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
        e_machine = (
            fields["e_machine"]
            if "e_machine" in fields
            else self.__executable_header.fields()["e_machine"]
        )
        if e_machine == self.__EM_X86_64 and e_flags != 0:
            raise ValueError("Nonzero e_flags unexpected for x86-64")

    def __validate_field_exists(self, field: str, fields: list):
        if field not in fields:
            raise ValueError(f"Unknown field {field}")
