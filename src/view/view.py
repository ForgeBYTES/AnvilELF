from abc import ABC, abstractmethod

from src.elf.executable_header import ExecutableHeader
from src.elf.section import Disassemblable, Section, Sections


class Printable(ABC):
    @abstractmethod
    def print(self) -> None:
        pass  # pragma: no cover


class PrintableExecutableHeader(Printable):
    def __init__(self, executable_header: ExecutableHeader):
        self.__executable_header = executable_header

    def print(self) -> None:
        fields = self.__executable_header.fields()
        print(
            "Executable Header:",
            f"  Magic: {self.__magic(fields)}",
            f"  Class: {fields['e_ident']['EI_CLASS']}",
            f"  Data: {fields['e_ident']['EI_DATA']}",
            f"  Version: {fields['e_ident']['EI_VERSION']}",
            f"  OS/ABI: {fields['e_ident']['EI_OSABI']}",
            f"  ABI Version: {fields['e_ident']['EI_ABIVERSION']}",
            f"  Type: {fields['e_type']}",
            f"  Machine: {fields['e_machine']}",
            f"  Entry point: 0x{fields['e_entry']:x}",
            f"  Start of section headers: 0x{fields['e_shoff']:x}",
            f"  Number of section headers: {fields['e_shnum']}",
            sep="\n",
        )

    def __magic(self, fields: dict) -> str:
        return " ".join(f"{byte:02x}" for byte in fields["e_ident"]["EI_MAG"])


class PrintableSection(Printable):
    def __init__(self, section: Section, full: bool = False):
        self.__section = section
        self.__full = full

    def print(self) -> None:
        header = self.__section.header()
        data = (
            self.__section.data()
            if self.__full
            else self.__section.data()[:32]
        )
        print(
            "Section Header:",
            f"  Name: {header['sh_name']} (index in .shstrtab)",
            f"  Type: {header['sh_type']}",
            f"  Flags: 0x{header['sh_flags']:x}",
            f"  Address: 0x{header['sh_addr']:x}",
            f"  Offset: 0x{header['sh_offset']:x}",
            f"  Section size: {header['sh_size']} bytes",
            f"  Link: {header['sh_link']}",
            f"  Info: {header['sh_info']}",
            f"  Address alignment: {header['sh_addralign']}",
            f"  Section entry size: {header['sh_entsize']}",
            "Section:",
            f"  Name: {self.__section.name()}",
            f"  Data: {self.__hex_dump(data)}{self.__dots(self.__full)}",
            f"  ASCII: {self.__ascii_dump(data)}{self.__dots(self.__full)}",
            sep="\n",
        )

    def __hex_dump(self, data: bytes):
        return " ".join(f"{byte:02x}" for byte in data)

    def __ascii_dump(self, data: bytes):
        return "".join(
            chr(byte) if 32 <= byte <= 126 else "." for byte in data
        )

    def __dots(self, full: bool) -> str:
        return " ..." if not full else ""


class PrintableSections(Printable):
    def __init__(self, sections: Sections):
        self.__sections = sections

    def print(self) -> None:
        for index, section in enumerate(self.__sections.all()):
            print(f"[{index}] {section.name()}")


class PrintableDisassemblable(Printable):
    def __init__(
        self,
        disassemblable: Disassemblable,
        offset: int = 0,
        size: int = 0,
    ):
        self.__disassemblable = disassemblable
        self.__offset = offset
        self.__size = size

    def print(self) -> None:
        for line in self.__assembly(self.__offset, self.__size):
            print(line)

    def __assembly(self, offset: int, size: int) -> list[str]:
        assembly = self.__disassemblable.disassembly()
        return (
            assembly[offset : offset + size]  # noqa: E203
            if size
            else assembly[offset:]
        )
