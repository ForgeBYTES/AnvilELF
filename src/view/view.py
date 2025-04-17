from abc import ABC, abstractmethod

from src.elf.executable_header import ExecutableHeader
from src.elf.section import (
    Disassemblable,
    Section,
    Sections,
    Symbol,
    SymbolTable,
)


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
    def __init__(self, sections: Sections, full: bool = False):
        self.__sections = sections
        self.__full = full

    def print(self) -> None:
        if self.__full:
            self.__full_print(self.__sections)
        else:
            self.__simple_print(self.__sections)

    def __simple_print(self, sections: Sections) -> None:
        for index, section in enumerate(sections.all()):
            print(f"{f'[{index}]':>4} {section.name()}")

    def __full_print(self, sections: Sections):
        print(
            f"{'Idx':<4} {'Name':<20} {'Type':<10} {'Flags':<10} "
            f"{'Address':<12} {'Offset':<10} {'Size':<6} "
            f"{'Link':<5} {'Info':<5} {'Align':<6} {'ES':<3}"
        )
        for index, section in enumerate(sections.all()):
            header = section.header()
            print(
                f"{f'[{index}]':<4} "
                f"{section.name():<20} "
                f"{header['sh_type']:<10} "
                f"0x{header['sh_flags']:08x} "
                f"0x{header['sh_addr']:08x}   "
                f"0x{header['sh_offset']:06x}   "
                f"{header['sh_size']:<6} "
                f"{header['sh_link']:<5} "
                f"{header['sh_info']:<5} "
                f"{header['sh_addralign']:<6} "
                f"{header['sh_entsize']:<3}"
            )


class PrintableSymbolTable(Printable):
    def __init__(self, symbol_table: SymbolTable):
        self.__symbol_table = symbol_table

    def print(self) -> None:
        print(f"Symbol Table: {self.__symbol_table.name()}")
        print(
            f"{'Idx':<4}  {'Value':<18}  {'Size':>5}  {'Bind':<8}  "
            f"{'Type':<8}  {'Vis':<10}  {'Name'}"
        )
        for index, symbol in enumerate(self.__symbol_table.symbols()):
            fields = symbol.fields()
            print(
                f"{f'[{index}]':<4}  "
                f"0x{fields['st_value']:016x}  "
                f"{fields['st_size']:<5}  "
                f"{self.__bind_name(symbol.bind()):<8}  "
                f"{self.__type_name(symbol.type()):<8}  "
                f"{self.__visibility_name(symbol.visibility()):<10}  "
                f"{symbol.name()}"
            )

    def __bind_name(self, bind: int) -> str:
        return {
            Symbol._STB_LOCAL: "LOCAL",
            Symbol._STB_GLOBAL: "GLOBAL",
            Symbol._STB_WEAK: "WEAK",
        }.get(bind, f"{bind}")

    def __type_name(self, _type: int) -> str:
        return {
            Symbol._STT_NOTYPE: "NOTYPE",
            Symbol._STT_OBJECT: "OBJECT",
            Symbol._STT_FUNC: "FUNC",
            Symbol._STT_SECTION: "SECTION",
            Symbol._STT_FILE: "FILE",
        }.get(_type, f"{_type}")

    def __visibility_name(self, visibility: int) -> str:
        return {
            Symbol._STV_DEFAULT: "DEFAULT",
            Symbol._STV_INTERNAL: "INTERNAL",
            Symbol._STV_HIDDEN: "HIDDEN",
            Symbol._STV_PROTECTED: "PROTECTED",
        }.get(visibility, f"{visibility}")


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
