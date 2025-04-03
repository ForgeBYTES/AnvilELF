from abc import ABC, abstractmethod
from functools import cached_property

import capstone

from src.elf.executable_header import ExecutableHeader
from src.elf.section_header import SectionHeader, SectionHeaders


class Section(ABC):
    @abstractmethod
    def header(self) -> dict:
        pass  # pragma: no cover

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


class Shstrtab(Section):
    @abstractmethod
    def name_by_index(self, sh_name: int) -> str:
        pass  # pragma: no cover


class Disassemblable(Section):
    @abstractmethod
    def disassembly(self) -> list[str]:
        pass  # pragma: no cover


class RawSection(Section):
    def __init__(
        self,
        raw_data: bytearray,
        header: SectionHeader,
        shstrtab: Shstrtab | None = None,
    ):
        self.__raw_data = raw_data
        self.__section_header = header
        self.__shstrtab = shstrtab

    def header(self) -> dict:
        return self.__section_header.fields()

    def data(self) -> bytes:
        fields = self.__section_header.fields()
        return self.__raw_data[
            fields["sh_offset"] : fields["sh_offset"]  # noqa: E203
            + fields["sh_size"]
        ]

    def name(self) -> str:
        if self.__shstrtab is None:
            return str(self.__section_header.fields()["sh_name"])

        return self.__shstrtab.name_by_index(
            self.__section_header.fields()["sh_name"]
        )


class RawShstrtabSection(Shstrtab):
    def __init__(self, origin: Section):
        self.__origin = origin

    def name_by_index(self, sh_name: int) -> str:
        data = self.data()
        return data[
            sh_name : data.find(b"\x00", sh_name)  # noqa: E203
        ].decode("ascii")

    def header(self) -> dict:
        return self.__origin.header()  # pragma: no cover

    def data(self) -> bytes:
        return self.__origin.data()

    def name(self) -> str:
        return ".shstrtab"  # pragma: no cover


class RawTextSection(Disassemblable):
    def __init__(self, origin: Section):
        self.__origin = origin
        self.__cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def disassembly(self) -> list[str]:
        self.__cs.syntax = capstone.CS_OPT_SYNTAX_INTEL
        return [
            self.__instruction(
                instruction.address,
                instruction.mnemonic,
                instruction.op_str,
            )
            for instruction in self.__cs.disasm(
                self.data(),
                self.header()["sh_addr"],
            )
        ]

    def header(self) -> dict:
        return self.__origin.header()

    def data(self) -> bytes:
        return self.__origin.data()

    def name(self) -> str:
        return ".text"  # pragma: no cover

    def __instruction(self, address: str, mnemonic: str, op: str):
        return f"{address:08x}: {mnemonic} {op}".rstrip()


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

    def all(self) -> list[Section]:
        headers = self.__section_headers.all()
        e_shstrndx = self.__executable_header.fields()["e_shstrndx"]
        return [
            RawSection(
                self.__raw_data,
                header,
                RawShstrtabSection(
                    RawSection(self.__raw_data, headers[e_shstrndx])
                ),
            )
            for header in headers
        ]


class CachedSection(Section):
    def __init__(self, origin: Section):
        self.__origin = origin

    def name(self) -> str:
        return self.__cached_name

    def data(self) -> bytes:
        return self.__cached_data

    def header(self) -> dict:
        return self.__cached_header  # pragma: no cover

    @cached_property
    def __cached_name(self) -> str:
        return self.__origin.name()

    @cached_property
    def __cached_data(self) -> bytes:
        return self.__origin.data()

    @cached_property
    def __cached_header(self) -> dict:
        return self.__origin.header()  # pragma: no cover


class CachedSections(Sections):
    def __init__(
        self,
        raw_data: bytearray,
        section_headers: SectionHeaders,
        executable_header: ExecutableHeader,
    ):
        self.__raw_data = raw_data
        self.__section_headers = section_headers
        self.__executable_header = executable_header

    def all(self) -> list[Section]:
        headers = self.__section_headers.all()
        e_shstrndx = self.__executable_header.fields()["e_shstrndx"]
        return [
            CachedSection(
                RawSection(
                    self.__raw_data,
                    header,
                    RawShstrtabSection(
                        CachedSection(
                            RawSection(self.__raw_data, headers[e_shstrndx])
                        )
                    ),
                )
            )
            for header in headers
        ]
