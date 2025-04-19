from abc import ABC, abstractmethod

from src.elf.executable_header import (
    ExecutableHeader,
    RawExecutableHeader,
    ValidatedExecutableHeader,
)
from src.elf.section import RawSections, Sections
from src.elf.section_header import (
    RawSectionHeaders,
    SectionHeaders,
    ValidatedSectionHeaders,
)


class Binary(ABC):
    @abstractmethod
    def components(self) -> tuple[ExecutableHeader, SectionHeaders, Sections]:
        pass  # pragma: no cover

    @abstractmethod
    def save(self) -> None:
        pass  # pragma: no cover

    @abstractmethod
    def raw_data(self) -> bytearray:
        pass  # pragma: no cover


class RawBinary(Binary):
    def __init__(self, path: str):
        self.__path = path
        self.__raw_data: bytearray | None = None

    def components(self) -> tuple[ExecutableHeader, SectionHeaders, Sections]:
        raw_data = self.raw_data()
        executable_header = RawExecutableHeader(raw_data)
        section_headers = RawSectionHeaders(raw_data, executable_header)
        return (
            executable_header,
            section_headers,
            RawSections(
                raw_data,
                section_headers,
                executable_header,
            ),
        )

    def raw_data(self) -> bytearray:
        if self.__raw_data is None:
            try:
                with open(self.__path, "rb") as file:
                    self.__raw_data = bytearray(file.read())
            except OSError:
                raise ValueError("Failed to load binary")
        return self.__raw_data

    def save(self) -> None:
        try:
            with open(self.__path, "wb") as file:
                file.write(self.raw_data())
        except OSError:
            raise ValueError("Failed to save binary")


class ValidatedBinary(Binary):
    def __init__(self, origin: Binary):
        self.__origin = origin

    def components(self) -> tuple[ExecutableHeader, SectionHeaders, Sections]:
        raw_data = self.raw_data()
        executable_header = ValidatedExecutableHeader(
            RawExecutableHeader(raw_data)
        )
        section_headers = ValidatedSectionHeaders(
            RawSectionHeaders(raw_data, executable_header)
        )
        return (
            executable_header,
            section_headers,
            RawSections(
                raw_data,
                section_headers,
                executable_header,
            ),
        )

    def raw_data(self) -> bytearray:
        return self.__origin.raw_data()

    def save(self) -> None:
        self.__origin.save()
