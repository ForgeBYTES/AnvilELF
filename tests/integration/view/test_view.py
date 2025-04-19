import re

import pytest
from _pytest.capture import CaptureFixture
from _pytest.fixtures import FixtureRequest

from src.elf.executable_header import RawExecutableHeader
from src.elf.section import (
    RawDisassembly,
    RawSection,
    RawSections,
    RawStringTable,
    RawSymbolTable,
)
from src.elf.section_header import RawSectionHeaders
from src.view.view import (
    PrintableDisassembly,
    PrintableExecutableHeader,
    PrintableSection,
    PrintableSections,
    PrintableSymbolTable,
)


@pytest.fixture
def raw_data(request: FixtureRequest) -> bytearray:
    with open(request.param, "rb") as binary:
        return bytearray(binary.read())


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_printing_executable_header(
    raw_data: bytearray, capsys: CaptureFixture[str]
) -> None:
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
        "  Entry point: 0x1260\n"
        "  Start of section headers: 0x4b20\n"
        "  Number of section headers: 39\n"
    )

    PrintableExecutableHeader(RawExecutableHeader(raw_data)).print()

    assert capsys.readouterr().out == expected_output


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_printing_section(
    raw_data: bytearray, capsys: CaptureFixture[str]
) -> None:
    expected_output = (
        "Section Header:\n"
        "  Name: 17 (index in .shstrtab)\n"
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
        "  Data: 00 2e 73 79 6d 74 61 62 00 2e 73 74 72 74 61 62 00 2e 73 68 "
        "73 74 72 74 61 62 00 2e 69 6e 74 65 ...\n"
        "  ASCII: ..symtab..strtab..shstrtab..inte ...\n"
    )

    executable_header = RawExecutableHeader(raw_data)

    PrintableSection(
        RawSection(
            raw_data,
            RawSectionHeaders(raw_data, executable_header).all()[
                executable_header.fields()["e_shstrndx"]
            ],
        )
    ).print()

    assert capsys.readouterr().out == expected_output


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_printing_full_section(
    raw_data: bytearray, capsys: CaptureFixture[str]
) -> None:
    patterns = [
        r"Section Header:\n\s+Name:\s+\d+ \(index in \.shstrtab\)",
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
        r"Data:\s+([0-9a-fA-F]{2} ?)",
        r"ASCII:\s+.",
    ]

    executable_header = RawExecutableHeader(raw_data)

    PrintableSection(
        RawSection(
            raw_data,
            RawSectionHeaders(raw_data, executable_header).all()[
                executable_header.fields()["e_shstrndx"]
            ],
        ),
        full=True,
    ).print()

    output = capsys.readouterr().out

    for pattern in patterns:
        assert re.search(pattern, output) is not None


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_printing_sections(
    raw_data: bytearray, capsys: CaptureFixture[str]
) -> None:
    # fmt: off
    expected_output = (
        " [0] \n [1] .interp\n [2] .note.gnu.property\n"
        " [3] .note.gnu.build-id\n [4] .note.ABI-tag\n [5] .gnu.hash\n"
        " [6] .dynsym\n [7] .dynstr\n [8] .gnu.version\n [9] .gnu.version_r\n"
        "[10] .rela.dyn\n[11] .rela.plt\n[12] .init\n[13] .plt\n"
        "[14] .plt.got\n[15] .plt.sec\n[16] .text\n[17] .fini\n[18] .rodata\n"
        "[19] .eh_frame_hdr\n[20] .eh_frame\n[21] .init_array\n"
        "[22] .fini_array\n[23] .dynamic\n[24] .got\n[25] .data\n[26] .bss\n"
        "[27] .comment\n[28] .shstrtab\n"
    )
    # fmt: on

    executable_header = RawExecutableHeader(raw_data)

    PrintableSections(
        RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        )
    ).print()

    assert capsys.readouterr().out == expected_output


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_printing_full_sections(
    raw_data: bytearray, capsys: CaptureFixture[str]
) -> None:
    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    PrintableSections(sections, full=True).print()

    output = capsys.readouterr().out.strip().splitlines()

    assert re.match(
        r"\s*Idx\s+Name\s+Type\s+Flags\s+Address"
        r"\s+Offset\s+Size\s+Link\s+Info\s+Align\s+ES",
        output[0],
    )

    for line in output[1:]:
        assert (
            re.compile(
                (
                    r"^\s*\[\d+]\s+"
                    r"(?:\.\S+|\s+)\s+"
                    r"\d+\s+"
                    r"0x[0-9a-fA-F]+\s+"
                    r"0x[0-9a-fA-F]+\s+"
                    r"0x[0-9a-fA-F]+\s+"
                    r"\d+\s+"
                    r"\d+\s+"
                    r"\d+\s+"
                    r"\d+\s+"
                    r"\d+\s*$"
                )
            ).match(line)
            is not None
        )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_printing_symbol_table(
    raw_data: bytearray, capsys: CaptureFixture[str]
) -> None:
    expected_header = "Symbol Table: .dynsym"
    expected_columns = (
        "Idx   Value               Size   "
        "Bind      Type      Visibility  Name"
    )

    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    PrintableSymbolTable(
        RawSymbolTable(
            sections.find(".dynsym"),
            RawStringTable(sections.find(".dynstr")),
        ),
        ".dynsym",
    ).print()

    output = capsys.readouterr().out.splitlines()

    assert output[0] == expected_header
    assert output[1] == expected_columns

    for line in output[2:]:
        assert (
            re.compile(
                (
                    r"\[\d+\]\s+0x[0-9a-f]{16}\s+\d+\s+"
                    r"(LOCAL|GLOBAL|WEAK)\s+"
                    r"(NOTYPE|OBJECT|FUNC|SECTION|FILE|COMMON|TLS)\s+"
                    r"(DEFAULT|INTERNAL|HIDDEN|PROTECTED)\s+"
                    r"[\x20-\x7E]*"
                )
            ).match(line)
            is not None
        )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_printing_disassembly(
    raw_data: bytearray, capsys: CaptureFixture[str]
) -> None:
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

    PrintableDisassembly(
        RawDisassembly(sections.find(".text")),
    ).print()

    assert capsys.readouterr().out.startswith(expected_output)
