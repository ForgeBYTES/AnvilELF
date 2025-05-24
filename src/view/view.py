import json
from abc import ABC, abstractmethod

from src.elf.executable_header import ExecutableHeader
from src.elf.program_header import ProgramHeader
from src.elf.section import Disassembly, Section, Sections, Symbol, SymbolTable
from src.elf.segment import Dynamic, DynamicEntry, Segments


class Formattable(ABC):
    @abstractmethod
    def format(self) -> str:
        pass  # pragma: no cover


class FormattedExecutableHeader(Formattable):
    def __init__(
        self, executable_header: ExecutableHeader, as_json: bool = False
    ):
        self.__executable_header = executable_header
        self.__as_json = as_json

    def format(self) -> str:
        if self.__as_json:
            return self.__json(self.__executable_header)
        else:
            return self.__text(self.__executable_header)

    def __text(self, executable_header: ExecutableHeader) -> str:
        fields = executable_header.fields()
        e_ident = fields["e_ident"]
        return (
            "Executable Header:\n"
            f"  Magic: {self.__hex(e_ident['EI_MAG'])}\n"
            f"  Class: {e_ident['EI_CLASS']}\n"
            f"  Data: {e_ident['EI_DATA']}\n"
            f"  Version: {e_ident['EI_VERSION']}\n"
            f"  OS/ABI: {e_ident['EI_OSABI']}\n"
            f"  ABI Version: {e_ident['EI_ABIVERSION']}\n"
            f"  Type: {fields['e_type']}\n"
            f"  Machine: {fields['e_machine']}\n"
            f"  Version: {fields['e_version']}\n"
            f"  Entry point: 0x{fields['e_entry']:x}\n"
            f"  Start of program headers: 0x{fields['e_phoff']:x}\n"
            f"  Start of section headers: 0x{fields['e_shoff']:x}\n"
            f"  Flags: {fields['e_flags']}\n"
            f"  Executable header size: {fields['e_ehsize']} bytes\n"
            f"  Program header entry size: {fields['e_phentsize']}\n"
            f"  Number of program headers: {fields['e_phnum']}\n"
            f"  Section header entry size: {fields['e_shentsize']}\n"
            f"  Number of section headers: {fields['e_shnum']}\n"
            f"  Section header string table index: {fields['e_shstrndx']}\n"
        )

    def __json(self, executable_header: ExecutableHeader) -> str:
        fields = executable_header.fields()
        fields["e_ident"]["EI_MAG"] = self.__hex(fields["e_ident"]["EI_MAG"])
        fields["e_ident"]["EI_PAD"] = self.__hex(fields["e_ident"]["EI_PAD"])
        return json.dumps({"executable_header": fields}, indent=2)

    def __hex(self, value: bytes) -> str:
        return " ".join(f"{byte:02x}" for byte in value)


class FormattedSection(Formattable):
    def __init__(
        self, section: Section, full: bool = False, as_json: bool = False
    ):
        self.__section = section
        self.__full = full
        self.__as_json = as_json

    def format(self) -> str:
        if self.__as_json:
            return self.__json(self.__section, self.__full)
        else:
            return self.__text(self.__section, self.__full)

    def __text(self, section: Section, full: bool) -> str:
        header = section.header()
        data = self.__data(self.__section, full)
        suffix = self.__truncation_suffix(data, full)
        return (
            "Section Header:\n"
            f"  Name: {header['sh_name']}\n"
            f"  Type: {header['sh_type']}\n"
            f"  Flags: 0x{header['sh_flags']:x}\n"
            f"  Address: 0x{header['sh_addr']:x}\n"
            f"  Offset: 0x{header['sh_offset']:x}\n"
            f"  Section size: {header['sh_size']} bytes\n"
            f"  Link: {header['sh_link']}\n"
            f"  Info: {header['sh_info']}\n"
            f"  Address alignment: {header['sh_addralign']}\n"
            f"  Section entry size: {header['sh_entsize']}\n"
            "Section:\n"
            f"  Name: {self.__section.name()}\n"
            f"  Data: {self.__hex_dump(data)}{suffix}\n"
            f"  ASCII: {self.__ascii_dump(data)}{suffix}\n"
        )

    def __json(self, section: Section, full: bool) -> str:
        return json.dumps(
            {
                "section_header": section.header(),
                "name": section.name(),
                "data": self.__hex_dump(self.__data(section, full)),
            },
            indent=2,
        )

    def __data(self, section: Section, full: bool) -> bytes:
        data = section.raw_data()
        return data.tobytes() if full else data[:32].tobytes()

    def __hex_dump(self, data: bytes) -> str:
        return " ".join(f"{byte:02x}" for byte in data) if data else "---"

    def __ascii_dump(self, data: bytes) -> str:
        return (
            "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
            if data
            else "---"
        )

    def __truncation_suffix(self, data: bytes, full: bool) -> str:
        return " ..." if not full and data else ""


class FormattedSections(Formattable):
    def __init__(self, sections: Sections, as_json: bool = False):
        self.__sections = sections
        self.__as_json = as_json

    def format(self) -> str:
        if self.__as_json:
            return self.__json(self.__sections)
        else:
            return self.__text(self.__sections)

    def __text(self, sections: Sections) -> str:
        lines = [
            f"{'Idx':<4} {'Name':<25} {'Type':<10} {'Flags':<10} "
            f"{'Address':<12} {'Offset':<10} {'Size':<6} "
            f"{'Link':<5} {'Info':<5} {'Align':<6} {'ES':<3}"
        ]
        for index, section in enumerate(sections.all()):
            header = section.header()
            name = self.__name(section, header)
            lines.append(
                f"{f'[{index}]':<4} {name:<25} "
                f"{header['sh_type']:<10} "
                f"0x{header['sh_flags']:08x} "
                f"0x{header['sh_addr']:08x}   "
                f"0x{header['sh_offset']:06x}   "
                f"{header['sh_size']:<6} "
                f"{header['sh_link']:<5} {header['sh_info']:<5} "
                f"{header['sh_addralign']:<6} {header['sh_entsize']:<3}"
            )
        return "\n".join(lines)

    def __json(self, sections: Sections) -> str:
        return json.dumps(
            {
                "sections": [
                    {
                        "section_header": section.header(),
                        "name": section.name(),
                    }
                    for section in sections.all()
                ],
            },
            indent=2,
        )

    def __name(self, section: Section, header: dict[str, int]) -> str:
        name = section.name()
        if name == "" or name == str(header["sh_name"]):
            return name
        return f"{name} ({header['sh_name']})"


class FormattedSymbolTable(Formattable):
    def __init__(
        self, symbol_table: SymbolTable, name: str, as_json: bool = False
    ):
        self.__symbol_table = symbol_table
        self.__name = name
        self.__as_json = as_json

    def format(self) -> str:
        if self.__as_json:
            return self.__json(self.__symbol_table, self.__name)
        else:
            return self.__text(self.__symbol_table, self.__name)

    def __text(self, symbol_table: SymbolTable, name: str) -> str:
        lines = [
            f"Symbol Table: {name}",
            f"{'Idx':<4}  {'Value':<18}  {'Size':<5}  {'Bind':<8}  "
            f"{'Type':<8}  {'Visibility':<10}  {'Name'}",
        ]
        for index, symbol in enumerate(symbol_table.symbols()):
            fields = symbol.fields()
            lines.append(
                f"{f'[{index}]':<4}  "
                f"0x{fields['st_value']:016x}  "
                f"{fields['st_size']:<5}  "
                f"{self.__bind_name(symbol.bind()):<8}  "
                f"{self.__type_name(symbol.type()):<8}  "
                f"{self.__visibility_name(symbol.visibility()):<10}  "
                f"{symbol.name()}"
            )
        return "\n".join(lines)

    def __json(self, symbol_table: SymbolTable, name: str) -> str:
        return json.dumps(
            {
                "symbol_table": name,
                "symbols": [
                    {
                        "name": symbol.name(),
                        "bind": self.__bind_name(symbol.bind()),
                        "type": self.__type_name(symbol.type()),
                        "visibility": self.__visibility_name(
                            symbol.visibility()
                        ),
                        "fields": symbol.fields(),
                    }
                    for symbol in symbol_table.symbols()
                ],
            },
            indent=2,
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


class FormattedDisassembly(Formattable):
    def __init__(
        self,
        disassembly: Disassembly,
        offset: int = 0,
        size: int = 0,
        as_json: bool = False,
    ):
        self.__disassembly = disassembly
        self.__offset = offset
        self.__size = size
        self.__as_json = as_json

    def format(self) -> str:
        if self.__as_json:
            return self.__json(self.__disassembly, self.__offset, self.__size)
        else:
            return self.__text(self.__disassembly, self.__offset, self.__size)

    def __text(self, disassembly: Disassembly, offset: int, size: int) -> str:
        return "\n".join(disassembly.instructions(offset, size))

    def __json(self, disassembly: Disassembly, offset: int, size: int) -> str:
        return json.dumps(
            {
                "offset": offset,
                "size": size,
                "instructions": disassembly.instructions(offset, size),
            },
            indent=2,
        )


class FormattedSegments(Formattable):
    def __init__(self, segments: Segments, as_json: bool = False):
        self.__segments = segments
        self.__as_json = as_json

    def format(self) -> str:
        if self.__as_json:
            return self.__json(self.__segments)
        else:
            return self.__text(self.__segments)

    def __text(self, segments: Segments) -> str:
        lines = [
            f"{'Idx':<4} {'Type':<15} {'Flags':<10} {'Offset':<10} "
            f"{'VirtAddr':<12} {'PhysAddr':<12} {'FileSize':<10} "
            f"{'MemSize':<10} {'Align':<6}"
        ]
        for index, segment in enumerate(segments.all()):
            header = segment.header()
            lines.append(
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
        return "\n".join(lines)

    def __json(self, segments: Segments) -> str:
        return json.dumps(
            {
                "segments": [
                    {
                        "program_header": header,
                        "type": self.__type(header["p_type"]),
                        "flags": self.__flags(header["p_flags"]),
                    }
                    for header in (
                        segment.header() for segment in segments.all()
                    )
                ]
            },
            indent=2,
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


class FormattedDynamic(Formattable):
    def __init__(self, dynamic: Dynamic, as_json: bool = False):
        self.__dynamic = dynamic
        self.__as_json = as_json

    def format(self) -> str:
        if self.__as_json:
            return self.__json(self.__dynamic)
        else:
            return self.__text(self.__dynamic)

    def __text(self, dynamic: Dynamic) -> str:
        lines = [f"{'Idx':<4} {'Tag':<20} {'Value'}"]
        for index, entry in enumerate(dynamic.all()):
            fields = entry.fields()
            lines.append(
                f"{f'[{index}]':<4} "
                f"{self.__tag(fields['d_tag']):<20} {fields['d_un']}"
            )
        return "\n".join(lines)

    def __json(self, dynamic: Dynamic) -> str:
        return json.dumps(
            {
                "dynamic": [
                    {
                        "tag": self.__tag(fields["d_tag"]),
                        "fields": fields,
                    }
                    for fields in (entry.fields() for entry in dynamic.all())
                ]
            },
            indent=2,
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
