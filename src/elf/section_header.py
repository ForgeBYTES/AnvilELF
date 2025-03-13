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

    @abstractmethod
    def fields(self) -> dict:
        pass


class SectionHeaders(ABC):
    _HEADER_SIZE = 64

    @abstractmethod
    def all(self) -> list[SectionHeader]:
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
        try:
            with open(filename, "rb") as file:
                file.seek(offset)
                return file.read(count * size)
        except OSError:
            raise ValueError("Failed to read file")
