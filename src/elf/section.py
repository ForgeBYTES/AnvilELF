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

    @abstractmethod
    def __str__(self) -> str:  # pragma: no cover
        pass


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
        ].decode("ascii")

    def __str__(self) -> str:
        fields = self.__section_header.fields()
        data = self.data()[:32]
        return (
            "Section:\n"
            f"  Section: {self.name()}\n"
            f"  Offset: 0x{fields['sh_offset']:08x}\n"
            f"  Size: 0x{fields['sh_size']:08x} ({fields['sh_size']} bytes)\n"
            f"  Data: {self.__hex_dump(data)} ...\n"
            f"  ASCII: {self.__ascii_dump(data)} ...\n"
        )

    def __hex_dump(self, data: bytes):
        return " ".join(f"{byte:02x}" for byte in data)

    def __ascii_dump(self, data: bytes):
        return "".join(
            chr(byte) if 32 <= byte <= 126 else "." for byte in data
        )


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
