from abc import ABC, abstractmethod

from src.elf.executable_header import ExecutableHeader
from src.elf.program_header import ProgramHeader
from src.elf.section import Disassembly, Section, Sections, Symbol, SymbolTable
from src.elf.segment import Dynamic, DynamicEntry, Segments


class Printable(ABC):
    @abstractmethod
    def print(self) -> None:
        pass  # pragma: no cover


class PrintableExecutableHeader(Printable):
    def __init__(self, executable_header: ExecutableHeader):
        self.__executable_header = executable_header

    def print(self) -> None:
        fields = self.__executable_header.fields()
        e_ident = fields["e_ident"]
        print(
            "Executable Header:",
            f"  Magic: {self.__magic(e_ident['EI_MAG'])}",
            f"  Class: {e_ident['EI_CLASS']}",
            f"  Data: {e_ident['EI_DATA']}",
            f"  Version: {e_ident['EI_VERSION']}",
            f"  OS/ABI: {e_ident['EI_OSABI']}",
            f"  ABI Version: {e_ident['EI_ABIVERSION']}",
            f"  Type: {fields['e_type']}",
            f"  Machine: {fields['e_machine']}",
            f"  Version: {fields['e_version']}",
            f"  Entry point: 0x{fields['e_entry']:x}",
            f"  Start of program headers: 0x{fields['e_phoff']:x}",
            f"  Start of section headers: 0x{fields['e_shoff']:x}",
            f"  Flags: {fields['e_flags']}",
            f"  Executable header size: {fields['e_ehsize']} bytes",
            f"  Program header entry size: {fields['e_phentsize']}",
            f"  Number of program headers: {fields['e_phnum']}",
            f"  Section header entry size: {fields['e_shentsize']}",
            f"  Number of section headers: {fields['e_shnum']}",
            f"  Section header string table index: {fields['e_shstrndx']}",
            sep="\n",
        )

    def __magic(self, ei_mag: bytes) -> str:
        return " ".join(f"{byte:02x}" for byte in ei_mag)


class PrintableSection(Printable):
    def __init__(self, section: Section, full: bool = False):
        self.__section = section
        self.__full = full

    def print(self) -> None:
        header = self.__section.header()
        data = self.__data(self.__section)
        suffix = self.__truncation_suffix(data)
        print(
            "Section Header:",
            f"  Name: {header['sh_name']}",
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
            f"  Data: {self.__hex_dump(data)}{suffix}",
            f"  ASCII: {self.__ascii_dump(data)}{suffix}",
            sep="\n",
        )

    def __data(self, section: Section) -> bytes:
        data = section.raw_data()
        return data.tobytes() if self.__full else data[:32].tobytes()

    def __hex_dump(self, data: bytes) -> str:
        return " ".join(f"{byte:02x}" for byte in data) if data else "---"

    def __ascii_dump(self, data: bytes) -> str:
        return (
            "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
            if data
            else "---"
        )

    def __truncation_suffix(self, data: bytes) -> str:
        return " ..." if not self.__full and data else ""


class PrintableSections(Printable):
    def __init__(self, sections: Sections, full: bool = False):
        self.__sections = sections
        self.__full = full

    def print(self) -> None:
        if self.__full:
            self.__print_full(self.__sections)
        else:
            self.__print_simple(self.__sections)

    def __print_simple(self, sections: Sections) -> None:
        for index, section in enumerate(sections.all()):
            print(f"{f'[{index}]':>4} {section.name()}")

    def __print_full(self, sections: Sections) -> None:
        print(
            f"{'Idx':<4} {'Name':<25} {'Type':<10} {'Flags':<10} "
            f"{'Address':<12} {'Offset':<10} {'Size':<6} "
            f"{'Link':<5} {'Info':<5} {'Align':<6} {'ES':<3}"
        )
        for index, section in enumerate(sections.all()):
            header = section.header()
            print(
                f"{f'[{index}]':<4} "
                f"{self.__name(section, header):<25} "
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

    def __name(self, section: Section, header: dict[str, int]) -> str:
        name = section.name()
        if name == "" or name == str(header["sh_name"]):
            return name
        return f"{name} ({header['sh_name']})"


class PrintableSymbolTable(Printable):
    def __init__(self, symbol_table: SymbolTable, name: str):
        self.__symbol_table = symbol_table
        self.__name = name

    def print(self) -> None:
        print(f"Symbol Table: {self.__name}")
        print(
            f"{'Idx':<4}  {'Value':<18}  {'Size':<5}  {'Bind':<8}  "
            f"{'Type':<8}  {'Visibility':<3}  {'Name'}"
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
            Symbol.STB_LOCAL: "LOCAL",
            Symbol.STB_GLOBAL: "GLOBAL",
            Symbol.STB_WEAK: "WEAK",
        }.get(bind, f"{bind}")

    def __type_name(self, _type: int) -> str:
        return {
            Symbol.STT_NOTYPE: "NOTYPE",
            Symbol.STT_OBJECT: "OBJECT",
            Symbol.STT_FUNC: "FUNC",
            Symbol.STT_SECTION: "SECTION",
            Symbol.STT_FILE: "FILE",
        }.get(_type, f"{_type}")

    def __visibility_name(self, visibility: int) -> str:
        return {
            Symbol.STV_DEFAULT: "DEFAULT",
            Symbol.STV_INTERNAL: "INTERNAL",
            Symbol.STV_HIDDEN: "HIDDEN",
            Symbol.STV_PROTECTED: "PROTECTED",
        }.get(visibility, f"{visibility}")


class PrintableDisassembly(Printable):
    def __init__(
        self,
        disassembly: Disassembly,
        offset: int = 0,
        size: int = 0,
    ):
        self.__disassembly = disassembly
        self.__offset = offset
        self.__size = size

    def print(self) -> None:
        for instruction in self.__instructions(
            self.__disassembly, self.__offset, self.__size
        ):
            print(instruction)

    def __instructions(
        self, disassembly: Disassembly, offset: int, size: int
    ) -> list[str]:
        instructions = disassembly.instructions()
        return (
            instructions[offset : offset + size]
            if size
            else instructions[offset:]
        )


class PrintableSegments(Printable):
    def __init__(self, segments: Segments, full: bool = False):
        self.__segments = segments
        self.__full = full

    def print(self) -> None:
        if self.__full:
            self.__print_full(self.__segments)
        else:
            self.__print_simple(self.__segments)

    def __print_simple(self, segments: Segments) -> None:
        print(
            f"{'Idx':<4} {'Type':<15} {'Flags':<10} {'Offset':<10} "
            f"{'FileSize'}"
        )
        for index, segment in enumerate(segments.all()):
            header = segment.header()
            print(
                f"{f'[{index}]':<4} "
                f"{self.__type(header['p_type']):<15} "
                f"{self.__flags(header['p_flags']):<10} "
                f"0x{header['p_offset']:06x}   "
                f"{header['p_filesz']:<10}"
            )

    def __print_full(self, segments: Segments) -> None:
        print(
            f"{'Idx':<4} {'Type':<15} {'Flags':<10} {'Offset':<10} "
            f"{'VirtAddr':<12} {'PhysAddr':<12} {'FileSize':<10} "
            f"{'MemSize':<10} {'Align':<6}"
        )
        for index, segment in enumerate(segments.all()):
            header = segment.header()
            print(
                f"{f'[{index}]':<4} "
                f"{self.__type(header['p_type']):<15} "
                f"{self.__flags(header['p_flags']):<10} "
                f"0x{header['p_offset']:06x}   "
                f"0x{header['p_vaddr']:08x}   "
                f"0x{header['p_paddr']:08x}   "
                f"{header['p_filesz']:<10} "
                f"{header['p_memsz']:<10} "
                f"{header['p_align']:<6}"
            )

    def __type(self, p_type: int) -> str:
        return {
            ProgramHeader.PT_NULL: "NULL",
            ProgramHeader.PT_LOAD: "LOAD",
            ProgramHeader.PT_DYNAMIC: "DYNAMIC",
            ProgramHeader.PT_INTERP: "INTERP",
            ProgramHeader.PT_NOTE: "NOTE",
            ProgramHeader.PT_SHLIB: "SHLIB",
            ProgramHeader.PT_PHDR: "PHDR",
            ProgramHeader.PT_TLS: "TLS",
            ProgramHeader.GNU_EH_FRAME: "GNU_EH_FRAME",
            ProgramHeader.GNU_STACK: "GNU_STACK",
            ProgramHeader.GNU_RELRO: "GNU_RELRO",
            ProgramHeader.GNU_PROPERTY: "GNU_PROPERTY",
        }.get(p_type, f"{p_type}")

    def __flags(self, p_flags: int) -> str:
        return "".join(
            [
                "R" if p_flags & ProgramHeader.PF_R else "",
                "W" if p_flags & ProgramHeader.PF_W else "",
                "E" if p_flags & ProgramHeader.PF_X else "",
            ]
        )


class PrintableDynamic(Printable):
    def __init__(self, dynamic: Dynamic):
        self.__dynamic = dynamic

    def print(self) -> None:
        print(f"{'Idx':<4} {'Tag':<20} {'Value'}")
        for index, entry in enumerate(self.__dynamic.all()):
            fields = entry.fields()
            print(
                f"{f'[{index}]':<4} "
                f"{self.__tag(fields['d_tag']):<20} "
                f"{fields['d_un']}"
            )

    def __tag(self, tag: int) -> str:
        return {
            DynamicEntry.DT_NULL: "DT_NULL",
            DynamicEntry.DT_NEEDED: "DT_NEEDED",
            DynamicEntry.DT_PLTRELSZ: "DT_PLTRELSZ",
            DynamicEntry.DT_PLTGOT: "DT_PLTGOT",
            DynamicEntry.DT_HASH: "DT_HASH",
            DynamicEntry.DT_STRTAB: "DT_STRTAB",
            DynamicEntry.DT_SYMTAB: "DT_SYMTAB",
            DynamicEntry.DT_RELA: "DT_RELA",
            DynamicEntry.DT_RELASZ: "DT_RELASZ",
            DynamicEntry.DT_RELAENT: "DT_RELAENT",
            DynamicEntry.DT_STRSZ: "DT_STRSZ",
            DynamicEntry.DT_SYMENT: "DT_SYMENT",
            DynamicEntry.DT_INIT: "DT_INIT",
            DynamicEntry.DT_FINI: "DT_FINI",
            DynamicEntry.DT_SONAME: "DT_SONAME",
            DynamicEntry.DT_RPATH: "DT_RPATH",
            DynamicEntry.DT_SYMBOLIC: "DT_SYMBOLIC",
            DynamicEntry.DT_REL: "DT_REL",
            DynamicEntry.DT_RELSZ: "DT_RELSZ",
            DynamicEntry.DT_RELENT: "DT_RELENT",
            DynamicEntry.DT_PLTREL: "DT_PLTREL",
            DynamicEntry.DT_DEBUG: "DT_DEBUG",
            DynamicEntry.DT_TEXTREL: "DT_TEXTREL",
            DynamicEntry.DT_JMPREL: "DT_JMPREL",
            DynamicEntry.DT_BIND_NOW: "DT_BIND_NOW",
            DynamicEntry.DT_INIT_ARRAY: "DT_INIT_ARRAY",
            DynamicEntry.DT_FINI_ARRAY: "DT_FINI_ARRAY",
            DynamicEntry.DT_INIT_ARRAYSZ: "DT_INIT_ARRAYSZ",
            DynamicEntry.DT_FINI_ARRAYSZ: "DT_FINI_ARRAYSZ",
            DynamicEntry.DT_RUNPATH: "DT_RUNPATH",
            DynamicEntry.DT_FLAGS: "DT_FLAGS",
            DynamicEntry.DT_PREINIT_ARRAY: "DT_PREINIT_ARRAY",
            DynamicEntry.DT_PREINIT_ARRAYSZ: "DT_PREINIT_ARRAYSZ",
            DynamicEntry.DT_MAXPOSTAGS: "DT_MAXPOSTAGS",
        }.get(tag, f"0x{tag:08x}")
