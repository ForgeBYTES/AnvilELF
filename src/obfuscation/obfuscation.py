from typing import Tuple

from src.elf.binary import Binary
from src.elf.executable_header import ExecutableHeader, RawExecutableHeader
from src.elf.section import Sections
from src.elf.section_header import RawSectionHeaders, SectionHeaders


class HeaderlessBinary(Binary):
    def __init__(self, origin: Binary):
        self.__origin = origin
        self.__stripped = False

    def components(self) -> Tuple[ExecutableHeader, SectionHeaders, Sections]:
        self.__ensure_stripped()
        return self.__origin.components()

    def raw_data(self) -> bytearray:
        self.__ensure_stripped()
        return self.__origin.raw_data()

    def save(self) -> None:
        self.__ensure_stripped()
        self.__origin.save()

    def __ensure_stripped(self) -> None:
        if not self.__stripped:
            self.__strip(self.__origin.raw_data())
            self.__stripped = True

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
