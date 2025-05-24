from abc import ABC, abstractmethod

from src.elf.binary import Binary
from src.elf.executable_header import ExecutableHeader, RawExecutableHeader
from src.elf.program_header import ProgramHeaders
from src.elf.section import Sections
from src.elf.section_header import RawSectionHeaders, SectionHeaders
from src.elf.segment import Segments


class Obfuscated(ABC):
    @abstractmethod
    def obfuscate(self) -> None:
        pass  # pragma: no cover


class HeaderlessBinary(Binary, Obfuscated):
    def __init__(self, origin: Binary):
        self.__origin = origin

    def components(
        self,
    ) -> tuple[
        ExecutableHeader, SectionHeaders, Sections, ProgramHeaders, Segments
    ]:
        return self.__origin.components()

    def raw_data(self) -> bytearray:
        return self.__origin.raw_data()

    def save(self) -> None:
        self.__origin.save()

    def obfuscate(self) -> None:
        self.__strip(self.__origin.raw_data())

    def __strip(self, raw_data: bytearray) -> None:
        executable_header = RawExecutableHeader(raw_data)
        self.__strip_section_headers(
            RawSectionHeaders(raw_data, executable_header)
        )
        self.__strip_executable_header(executable_header)

    def __strip_section_headers(self, section_headers: SectionHeaders) -> None:
        for section_header in section_headers.all():
            section_header.change(
                {field: 0 for field in section_header.fields()}
            )

    def __strip_executable_header(
        self, executable_header: ExecutableHeader
    ) -> None:
        fields = executable_header.fields()
        (
            fields["e_shoff"],
            fields["e_shentsize"],
            fields["e_shnum"],
            fields["e_shstrndx"],
        ) = (0, 0, 0, 0)
        executable_header.change(fields)
