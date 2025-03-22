from abc import ABC, abstractmethod

from src.elf.executable_header import ExecutableHeader
from src.elf.section_header import SectionHeader, SectionHeaders


class Section(ABC):
    @abstractmethod
    def data(self) -> bytes:
        pass  # pragma: no cover

    @abstractmethod
    def name(self) -> str:
        pass  # pragma: no cover


class Sections(ABC):
    @abstractmethod
    def all(self) -> list[Section]:
        pass  # pragma: no cover


class RawSection(Section):
    def __init__(
        self,
        raw_data: bytearray,
        header: SectionHeader,
        string_table: Section | None = None,
    ):
        self.__raw_data = raw_data
        self.__section_header = header
        self.__string_table = string_table

    def data(self) -> bytes:
        fields = self.__section_header.fields()
        return self.__raw_data[
            fields["sh_offset"] : fields["sh_offset"]  # noqa: E203
            + fields["sh_size"]
        ]

    def name(self) -> str:
        if self.__string_table is None:
            return str(self.__section_header.fields()["sh_name"])

        data = self.__string_table.data()
        sh_name = self.__section_header.fields()["sh_name"]
        return data[
            sh_name : data.find(b"\x00", sh_name)  # noqa: E203
        ].decode("utf-8")


class RawSections(ABC):
    def __init__(
        self,
        raw_data: bytearray,
        section_headers: SectionHeaders,
        executable_header: ExecutableHeader,
    ):
        self.__raw_data = raw_data
        self.__section_headers = section_headers
        self.__executable_header = executable_header

    def all(self) -> list[RawSection]:
        section_headers = self.__section_headers.all()
        string_table = RawSection(
            self.__raw_data,
            section_headers[self.__executable_header.fields()["e_shstrndx"]],
        )

        return [
            RawSection(self.__raw_data, section_header, string_table)
            for section_header in section_headers
        ]
