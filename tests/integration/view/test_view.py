import re

import pytest
from _pytest.fixtures import FixtureRequest

from src.elf.executable_header import RawExecutableHeader
from src.elf.program_header import ProgramHeader, RawProgramHeaders
from src.elf.section import (
    RawDisassembly,
    RawSection,
    RawSections,
    RawStringTable,
    RawSymbolTable,
)
from src.elf.section_header import RawSectionHeaders
from src.elf.segment import RawDynamic, RawSegments
from src.view.view import (
    FormattedDisassembly,
    FormattedDynamic,
    FormattedExecutableHeader,
    FormattedSection,
    FormattedSections,
    FormattedSegment,
    FormattedSegments,
    FormattedSymbolTable,
)


@pytest.fixture
def raw_data(request: FixtureRequest) -> bytearray:
    with open(request.param, "rb") as binary:
        return bytearray(binary.read())


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_formatting_executable_header(raw_data: bytearray) -> None:
    expected_output = (
        "Executable Header:\n"
        "  Magic: 7f 45 4c 46\n"
        "  Class: 2\n"
        "  Data: 1\n"
        "  Version: 1\n"
        "  OS/ABI: 0\n"
        "  ABI Version: 0\n"
        "  Type: 3\n"
        "  Machine: 62\n"
        "  Version: 1\n"
        "  Entry point: 0x1260\n"
        "  Start of program headers: 0x40\n"
        "  Start of section headers: 0x4b20\n"
        "  Flags: 0\n"
        "  Executable header size: 64 bytes\n"
        "  Program header entry size: 56\n"
        "  Number of program headers: 13\n"
        "  Section header entry size: 64\n"
        "  Number of section headers: 39\n"
        "  Section header string table index: 38"
    )

    assert (
        FormattedExecutableHeader(RawExecutableHeader(raw_data)).format()
        == expected_output
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_formatting_executable_header_as_json(raw_data: bytearray) -> None:
    expected_output = (
        "{\n"
        '  "executable_header": {\n'
        '    "e_ident": {\n'
        '      "ei_mag": "7f 45 4c 46",\n'
        '      "ei_class": 2,\n'
        '      "ei_data": 1,\n'
        '      "ei_version": 1,\n'
        '      "ei_osabi": 0,\n'
        '      "ei_abiversion": 0,\n'
        '      "ei_pad": "00 00 00 00 00 00 00"\n'
        "    },\n"
        '    "e_type": 3,\n'
        '    "e_machine": 62,\n'
        '    "e_version": 1,\n'
        '    "e_entry": 4704,\n'
        '    "e_phoff": 64,\n'
        '    "e_shoff": 19232,\n'
        '    "e_flags": 0,\n'
        '    "e_ehsize": 64,\n'
        '    "e_phentsize": 56,\n'
        '    "e_phnum": 13,\n'
        '    "e_shentsize": 64,\n'
        '    "e_shnum": 39,\n'
        '    "e_shstrndx": 38\n'
        "  }\n"
        "}"
    )

    assert (
        FormattedExecutableHeader(
            RawExecutableHeader(raw_data), as_json=True
        ).format()
        == expected_output
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_formatting_section(raw_data: bytearray) -> None:
    expected_output = (
        "Section Header:\n"
        "  Name: 17\n"
        "  Type: 3\n"
        "  Flags: 0x0\n"
        "  Address: 0x0\n"
        "  Offset: 0x357f\n"
        "  Section size: 282 bytes\n"
        "  Link: 0\n"
        "  Info: 0\n"
        "  Address alignment: 1\n"
        "  Section entry size: 0\n"
        "Section:\n"
        "  Name: 17\n"
        "  Data (32 bytes): \\x00\\x2e\\x73\\x79\\x6d\\x74\\x61\\x62\\x00\\"
        "x2e\\x73\\x74\\x72\\x74\\x61\\x62\\x00\\x2e\\x73\\x68\\x73\\x74\\"
        "x72\\x74\\x61\\x62\\x00\\x2e\\x69\\x6e\\x74\\x65\n"
        "  ASCII (32 bytes): ..symtab..strtab..shstrtab..inte"
    )

    executable_header = RawExecutableHeader(raw_data)

    assert (
        FormattedSection(
            RawSection(
                raw_data,
                RawSectionHeaders(raw_data, executable_header).all()[
                    executable_header.fields()["e_shstrndx"]
                ],
            )
        ).format()
        == expected_output
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_formatting_section_as_json(raw_data: bytearray) -> None:
    expected_output = (
        "{\n"
        '  "section_header": {\n'
        '    "sh_name": 17,\n'
        '    "sh_type": 3,\n'
        '    "sh_flags": 0,\n'
        '    "sh_addr": 0,\n'
        '    "sh_offset": 13695,\n'
        '    "sh_size": 282,\n'
        '    "sh_link": 0,\n'
        '    "sh_info": 0,\n'
        '    "sh_addralign": 1,\n'
        '    "sh_entsize": 0\n'
        "  },\n"
        '  "name": "17",\n'
        '  "data": "\\\\x00\\\\x2e\\\\x73\\\\x79\\\\x6d\\\\x74\\\\x61'
        "\\\\x62\\\\x00\\\\x2e\\\\x73\\\\x74\\\\x72\\\\x74\\\\x61\\\\x62"
        "\\\\x00\\\\x2e\\\\x73\\\\x68\\\\x73\\\\x74\\\\x72\\\\x74\\\\x61"
        '\\\\x62\\\\x00\\\\x2e\\\\x69\\\\x6e\\\\x74\\\\x65"\n'
        "}"
    )

    executable_header = RawExecutableHeader(raw_data)

    assert (
        FormattedSection(
            RawSection(
                raw_data,
                RawSectionHeaders(raw_data, executable_header).all()[
                    executable_header.fields()["e_shstrndx"]
                ],
            ),
            as_json=True,
        ).format()
        == expected_output
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_formatting_full_section(raw_data: bytearray) -> None:
    patterns = [
        r"Section Header:\n\s+Name:\s+\d+",
        r"Type:\s+\d+",
        r"Flags:\s+0x[0-9a-fA-F]+",
        r"Address:\s+0x[0-9a-fA-F]+",
        r"Offset:\s+0x[0-9a-fA-F]+",
        r"Section size:\s+\d+\s+bytes",
        r"Link:\s+\d+",
        r"Info:\s+\d+",
        r"Address alignment:\s+\d+",
        r"Section entry size:\s+\d+",
        r"Section:\n\s+Name:\s+\d+",
        r"Data \(\d+ bytes\):\s+(\\x[0-9a-fA-F]{2})+",
        r"ASCII \(\d+ bytes\):\s+.",
    ]

    executable_header = RawExecutableHeader(raw_data)

    for pattern in patterns:
        assert (
            re.search(
                pattern,
                FormattedSection(
                    RawSection(
                        raw_data,
                        RawSectionHeaders(raw_data, executable_header).all()[
                            executable_header.fields()["e_shstrndx"]
                        ],
                    ),
                    full=True,
                ).format(),
            )
            is not None
        )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_formatting_sections(raw_data: bytearray) -> None:
    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    _format = FormattedSections(sections).format()

    assert re.match(
        r"^\s*Idx\s+Name\s+Type\s+Flags\s+Address"
        r"\s+Offset\s+Size\s+Link\s+Info\s+Align\s+ES",
        _format,
    )
    assert re.search(
        r"^\[\d+]\s+"
        r"(?:\.\S+(?: \(\d+\))?|\(\d+\)|\s+)\s+"
        r"\d+\s+"
        r"0x[0-9a-fA-F]+\s+"
        r"0x[0-9a-fA-F]+\s+"
        r"0x[0-9a-fA-F]+\s+"
        r"\d+\s+"
        r"\d+\s+"
        r"\d+\s+"
        r"\d+\s+"
        r"\d+\s*$",
        _format,
        re.MULTILINE,
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_formatting_sections_as_json(raw_data: bytearray) -> None:
    patterns = [
        r'"sections"\s*:\s*\[',
        r'"name"\s*:\s*"\.[a-zA-Z0-9_.]+"',
        r'"sh_name"\s*:\s*\d+',
        r'"sh_offset"\s*:\s*\d+',
    ]

    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    _format = FormattedSections(sections, as_json=True).format()

    for pattern in patterns:
        assert re.search(pattern, _format)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_formatting_symbol_table(raw_data: bytearray) -> None:
    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    _format = FormattedSymbolTable(
        RawSymbolTable(
            sections.find(".dynsym"),
            RawStringTable(sections.find(".dynstr")),
        ),
        ".dynsym",
    ).format()

    assert re.match(
        r"^Symbol Table: \.\w+\nIdx\s+Value\s+Size\s+Bind\s+Type\s+"
        r"Visibility\s+Name",
        _format,
    )
    assert re.search(
        r"^\[\d+\]\s+0x[0-9a-f]{16}\s+\d+\s+"
        r"(LOCAL|GLOBAL|WEAK)\s+"
        r"(NOTYPE|OBJECT|FUNC|SECTION|FILE|COMMON|TLS)\s+"
        r"(DEFAULT|INTERNAL|HIDDEN|PROTECTED)\s+"
        r"[\x20-\x7E]*$",
        _format,
        re.MULTILINE,
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_formatting_symbol_table_as_json(raw_data: bytearray) -> None:
    patterns = [
        r'"symbol_table"\s*:\s*"\.dynsym"',
        r'"name"\s*:\s*"[a-zA-Z0-9_]+"',
        r'"bind"\s*:\s*"(LOCAL|GLOBAL|WEAK)"',
        r'"type"\s*:\s*"(FUNC|OBJECT|NOTYPE)"',
        r'"visibility"\s*:\s*"(DEFAULT|HIDDEN|PROTECTED)"',
        r'"st_name"\s*:\s*\d+',
        r'"st_info"\s*:\s*\d+',
        r'"st_shndx"\s*:\s*\d+',
    ]

    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    _format = FormattedSymbolTable(
        RawSymbolTable(
            sections.find(".dynsym"),
            RawStringTable(sections.find(".dynstr")),
        ),
        ".dynsym",
        as_json=True,
    ).format()

    for pattern in patterns:
        assert re.search(pattern, _format), f"Missing pattern: {pattern}"


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_formatting_disassembly(raw_data: bytearray) -> None:
    expected_output = (
        "00001060: endbr64\n"
        "00001064: xor ebp, ebp\n"
        "00001066: mov r9, rdx\n"
        "00001069: pop rsi\n"
        "0000106a: mov rdx, rsp\n"
        "0000106d: and rsp, 0xfffffffffffffff0\n"
        "00001071: push rax\n"
        "00001072: push rsp\n"
        "00001073: xor r8d, r8d\n"
        "00001076: xor ecx, ecx\n"
        "00001078: lea rdi, [rip + 0xca]\n"
        "0000107f: call qword ptr [rip + 0x2f53]\n"
        "00001085: hlt\n"
    )

    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    assert (
        FormattedDisassembly(
            RawDisassembly(sections.find(".text")),
        )
        .format()
        .startswith(expected_output)
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_formatting_disassembly_as_json(raw_data: bytearray) -> None:
    patterns = [
        r'"offset"\s*:\s*\d+',
        r'"size"\s*:\s*\d+',
        r'"instructions"\s*:\s*\[',
        r'"0*[0-9a-f]{4,}:\s+[a-z]+.*?"',
    ]

    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    _format = FormattedDisassembly(
        RawDisassembly(sections.find(".text")),
        as_json=True,
    ).format()

    for pattern in patterns:
        assert re.search(pattern, _format)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_formatting_segments(raw_data: bytearray) -> None:
    executable_header = RawExecutableHeader(raw_data)
    segments = RawSegments(
        raw_data,
        RawProgramHeaders(raw_data, executable_header),
    )

    _format = FormattedSegments(segments).format()

    assert re.match(
        r"^\s*Idx\s+Type\s+Flags\s+Offset\s+VirtAddr\s+PhysAddr\s+"
        r"FileSize\s+MemSize\s+Align",
        _format,
    )
    assert re.search(
        r"^\[\d+]\s+"
        r"\S+\s+"
        r"R?W?E?\s+"
        r"0x[0-9a-fA-F]{6}\s+"
        r"0x[0-9a-fA-F]{8}\s+"
        r"0x[0-9a-fA-F]{8}\s+"
        r"\d+\s+"
        r"\d+\s+"
        r"\d+\s*$",
        _format,
        re.MULTILINE,
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_formatting_segments_as_json(raw_data: bytearray) -> None:
    patterns = [
        r'"segments"\s*:\s*\[',
        r'"program_header"\s*:\s*\{',
        r'"p_type"\s*:\s*\d+',
        r'"p_offset"\s*:\s*\d+',
        r'"p_filesz"\s*:\s*\d+',
        r'"type"\s*:\s*"[A-Z_]+"',
        r'"flags"\s*:\s*"[RWX]+"',
    ]

    executable_header = RawExecutableHeader(raw_data)
    segments = RawSegments(
        raw_data,
        RawProgramHeaders(raw_data, executable_header),
    )

    _format = FormattedSegments(segments, as_json=True).format()

    for pattern in patterns:
        assert re.search(pattern, _format)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_formatting_segment(raw_data: bytearray) -> None:
    expected_output = (
        "Program Header:\n"
        "  Type: 1\n"
        "  Flags: 0x5\n"
        "  Offset: 0x1000\n"
        "  Virtual address: 0x1000\n"
        "  Physical address: 0x1000\n"
        "  File size: 389 bytes\n"
        "  Memory size: 389 bytes\n"
        "  Alignment: 4096\n"
        "Segment:\n"
        "  Type: 1\n"
        "  Data (32 bytes): \\xf3\\x0f\\x1e\\xfa\\x48\\x83\\xec\\x08\\x48\\"
        "x8b\\x05\\xd9\\x2f\\x00\\x00\\x48\\x85\\xc0\\x74\\x02\\xff\\xd0\\"
        "x48\\x83\\xc4\\x08\\xc3\\x00\\x00\\x00\\x00\\x00\n"
        "  ASCII (32 bytes): ....H...H.../..H..t...H........."
    )

    executable_header = RawExecutableHeader(raw_data)
    segments = RawSegments(
        raw_data,
        RawProgramHeaders(raw_data, executable_header),
    )

    assert (
        FormattedSegment(
            segments.occurrence(
                ProgramHeader.PT_LOAD,
                ProgramHeader.PF_R | ProgramHeader.PF_X,
            )
        ).format()
        == expected_output
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_formatting_segment_as_json(raw_data: bytearray) -> None:
    expected_output = (
        "{\n"
        '  "program_header": {\n'
        '    "p_type": 1,\n'
        '    "p_flags": 5,\n'
        '    "p_offset": 4096,\n'
        '    "p_vaddr": 4096,\n'
        '    "p_paddr": 4096,\n'
        '    "p_filesz": 389,\n'
        '    "p_memsz": 389,\n'
        '    "p_align": 4096\n'
        "  },\n"
        '  "type": "1",\n'
        '  "data": "\\\\xf3\\\\x0f\\\\x1e\\\\xfa\\\\x48\\\\x83\\\\xec\\\\'
        "x08\\\\x48\\\\x8b\\\\x05\\\\xd9\\\\x2f\\\\x00\\\\x00\\\\x48\\\\"
        "x85\\\\xc0\\\\x74\\\\x02\\\\xff\\\\xd0\\\\x48\\\\x83\\\\xc4\\\\"
        'x08\\\\xc3\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00"\n'
        "}"
    )

    executable_header = RawExecutableHeader(raw_data)
    segments = RawSegments(
        raw_data,
        RawProgramHeaders(raw_data, executable_header),
    )

    assert (
        FormattedSegment(
            segments.occurrence(
                ProgramHeader.PT_LOAD,
                ProgramHeader.PF_R | ProgramHeader.PF_X,
            ),
            as_json=True,
        ).format()
        == expected_output
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_formatting_dynamic_entries(raw_data: bytearray) -> None:
    segments = RawSegments(
        raw_data, RawProgramHeaders(raw_data, RawExecutableHeader(raw_data))
    )
    for segment in segments.all():
        if segment.header().fields()["p_type"] == ProgramHeader.PT_DYNAMIC:
            _format = FormattedDynamic(RawDynamic(segment)).format()

            assert re.match(
                r"^\s*Idx\s+Tag\s+Value",
                _format,
            )
            assert re.search(
                r"^\[\d+]\s+(DT_\w+|0x[0-9a-f]{8})\s+\d+$",
                _format,
                re.MULTILINE,
            )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_formatting_dynamic_entries_as_json(raw_data: bytearray) -> None:
    patterns = [
        r'"dynamic"\s*:\s*\[',
        r'"tag"\s*:\s*"(DT_[A-Z_]+|0x[0-9a-f]+)"',
        r'"fields"\s*:\s*\{',
        r'"d_tag"\s*:\s*\d+',
        r'"d_un"\s*:\s*\d+',
    ]

    segments = RawSegments(
        raw_data, RawProgramHeaders(raw_data, RawExecutableHeader(raw_data))
    )
    for segment in segments.all():
        if segment.header().fields()["p_type"] == ProgramHeader.PT_DYNAMIC:
            _format = FormattedDynamic(
                RawDynamic(segment), as_json=True
            ).format()

            for pattern in patterns:
                assert re.search(pattern, _format)
