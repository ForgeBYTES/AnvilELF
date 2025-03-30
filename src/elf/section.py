from abc import ABC, abstractmethod

import capstone

from src.elf.executable_header import ExecutableHeader
from src.elf.section_header import SectionHeader, SectionHeaders


class Section(ABC):
    @abstractmethod
    def header_fields(self) -> dict:  # pragma: no cover
        pass

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


class Shstrtab(ABC):
    @abstractmethod
    def name_by_index(self, sh_name: int) -> str:  # pragma: no cover
        pass

    @abstractmethod
    def index_by_name(self, name: str) -> int:  # pragma: no cover
        pass


class Disassemblable(ABC):
    @abstractmethod
    def disassembly(self) -> list[str]:  # pragma: no cover
        pass


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

    def header_fields(self) -> dict:
        return self.__section_header.fields()

    def data(self) -> bytes:
        fields = self.header_fields()
        return self.__raw_data[
            fields["sh_offset"] : fields["sh_offset"]  # noqa: E203
            + fields["sh_size"]
        ]

    def name(self) -> str:
        if self.__shstrtab is None:
            return str(self.header_fields()["sh_name"])

        return self.__shstrtab.name_by_index(self.header_fields()["sh_name"])

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


class RawShstrtabSection(Section, Shstrtab):
    def __init__(self, origin: Section):
        self.__origin = origin

    def header_fields(self) -> dict:
        return self.__origin.header_fields()  # pragma: no cover

    def name_by_index(self, sh_name: int) -> str:
        data = self.data()
        return data[
            sh_name : data.find(b"\x00", sh_name)  # noqa: E203
        ].decode("ascii")

    def index_by_name(self, name: str) -> int:
        needle = name.encode("ascii")

        offset = 0
        for part in self.data().split(b"\x00"):
            if part == needle:
                return offset
            offset += len(part) + 1

        raise ValueError(f"Section name '{name}' not found in .shstrtab")

    def data(self) -> bytes:
        return self.__origin.data()

    def name(self) -> str:
        return ".shstrtab"

    def __str__(self) -> str:
        return str(self.__origin)


class RawTextSection(Section, Disassemblable):
    def __init__(self, origin: Section):
        self.__origin = origin
        self.__cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def disassembly(self) -> list[str]:
        self.__cs.syntax = capstone.CS_OPT_SYNTAX_INTEL
        return [
            (
                f"{instruction.address:08x}: "
                f"{instruction.mnemonic} {instruction.op_str}"
            )
            for instruction in self.__cs.disasm(
                self.data(),
                self.header_fields()["sh_addr"],
            )
        ]

    def header_fields(self) -> dict:
        return self.__origin.header_fields()

    def data(self) -> bytes:
        return self.__origin.data()

    def name(self) -> str:
        return ".text"

    def __str__(self) -> str:
        instructions = "\n".join(
            [f"  {instruction}" for instruction in self.disassembly()]
        )
        return f"Disassembly:\n{instructions}"


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
        shstrtab = RawShstrtabSection(
            RawSection(
                self.__raw_data,
                headers[self.__executable_header.fields()["e_shstrndx"]],
            )
        )
        return [
            self.__section(
                shstrtab.name_by_index(header.fields()["sh_name"]),
                header,
                shstrtab,
            )
            for header in headers
        ]

    def by_name(self, name: str) -> Section:
        for section in self.all():
            if section.name() == name:
                return section
        raise ValueError(f"Section '{name}' not found")

    def __section(
        self, name: str, header: SectionHeader, shstrtab: RawShstrtabSection
    ) -> Section:
        match name:
            case ".shstrtab":
                return RawShstrtabSection(
                    RawSection(
                        self.__raw_data,
                        header,
                        shstrtab,
                    )
                )
            case ".text":
                return RawTextSection(
                    RawSection(self.__raw_data, header, shstrtab)
                )
            case _:
                return RawSection(self.__raw_data, header, shstrtab)
