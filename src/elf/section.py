from abc import ABC, abstractmethod

from src.elf.executable_header import ExecutableHeader
from src.elf.section_header import SectionHeader, SectionHeaders


class Section(ABC):
    @abstractmethod
    def data(self) -> bytes:  # pragma: no cover
        pass

    @abstractmethod
    def name(self) -> str:  # pragma: no cover
        pass

    @abstractmethod
    def __str__(self) -> str:  # pragma: no cover
        pass


class Sections(ABC):
    @abstractmethod
    def all(self) -> list[Section]:  # pragma: no cover
        pass

    @abstractmethod
    def by_name(self, name: str) -> Section:  # pragma: no cover
        pass


class StringTable(Section):
    @abstractmethod
    def name_by_index(self, sh_name: int) -> str:  # pragma: no cover
        pass

    @abstractmethod
    def index_by_name(self, name: str) -> int:  # pragma: no cover
        pass


class RawSection(Section):
    def __init__(
        self,
        raw_data: bytearray,
        header: SectionHeader,
        string_table: StringTable | None = None,
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

        return self.__string_table.name_by_index(
            self.__section_header.fields()["sh_name"]
        )

    def __str__(self) -> str:
        data = self.data()[:32]
        return str(self.__section_header) + (
            "Section:\n"
            f"  Name: {self.name()}\n"
            f"  Data: {self.__hex_dump(data)} ...\n"
            f"  ASCII: {self.__ascii_dump(data)} ...\n"
        )

    def __hex_dump(self, data: bytes):
        return " ".join(f"{byte:02x}" for byte in data)

    def __ascii_dump(self, data: bytes):
        return "".join(
            chr(byte) if 32 <= byte <= 126 else "." for byte in data
        )


class RawStringTable(StringTable):
    def __init__(self, origin: Section):
        self.__origin = origin

    def name_by_index(self, sh_name: int) -> str:
        data = self.__origin.data()
        return data[
            sh_name : data.find(b"\x00", sh_name)  # noqa: E203
        ].decode("ascii")

    def index_by_name(self, name: str) -> int:
        data = self.__origin.data()
        needle = name.encode("ascii")

        offset = 0
        while offset < len(data):
            if (end := data.find(b"\x00", offset)) == -1:
                break  # pragma: no cover
            if data[offset:end] == needle:
                return offset
            offset = end + 1

        raise ValueError(f"Name '{name}' not found in string table")

    def data(self) -> bytes:
        return self.__origin.data()  # pragma: no cover

    def name(self) -> str:
        return ".shstrtab"

    def __str__(self) -> str:
        return self.__origin.__str__()  # pragma: no cover


class RawSections(Sections):
    def __init__(
        self,
        raw_data: bytearray,
        section_headers: SectionHeaders,
        executable_header: ExecutableHeader,
    ):
        self.__raw_data = raw_data
        self.__section_headers = section_headers
        self.__executable_header = executable_header

    def all(self, name: str = "") -> list[Section]:
        section_headers = self.__section_headers.all()
        string_table = self.__string_table(section_headers)
        return [
            RawSection(self.__raw_data, section_header, string_table)
            for section_header in section_headers
        ]

    def by_name(self, name: str) -> Section:
        section_headers = self.__section_headers.all()
        string_table = self.__string_table(section_headers)

        match name:
            case ".shstrtab":
                return string_table
            case _:
                sh_name = string_table.index_by_name(name)

                for section_header in section_headers:
                    if section_header.fields()["sh_name"] == sh_name:
                        return RawSection(
                            self.__raw_data, section_header, string_table
                        )

        raise ValueError(f"Section '{name}' not found")  # pragma: no cover

    def __string_table(
        self, section_headers: list[SectionHeader]
    ) -> StringTable:
        return RawStringTable(
            RawSection(
                self.__raw_data,
                section_headers[
                    self.__executable_header.fields()["e_shstrndx"]
                ],
            )
        )
