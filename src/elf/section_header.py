import struct
from abc import ABC, abstractmethod


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
