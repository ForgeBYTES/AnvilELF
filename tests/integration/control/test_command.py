import re

import pytest
from _pytest.capture import CaptureFixture
from _pytest.fixtures import FixtureRequest

from src.control.command import (
    DynamicCommand,
    DynsymCommand,
    ExecutableHeaderCommand,
    FiniCommand,
    InitCommand,
    PltCommand,
    SectionCommand,
    SectionsCommand,
    SegmentsCommand,
    SymtabCommand,
    TextCommand,
)
from src.elf.executable_header import RawExecutableHeader
from src.elf.program_header import RawProgramHeaders
from src.elf.section import RawSections
from src.elf.section_header import RawSectionHeaders
from src.elf.segment import RawSegments


@pytest.fixture
def raw_data(request: FixtureRequest) -> bytearray:
    with open(request.param, "rb") as binary:
        return bytearray(binary.read())


@pytest.mark.parametrize(
    "validated",
    [True, False],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_executable_header_command_with_all_flags(
    raw_data: bytearray, capsys: CaptureFixture[str], validated: bool
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
        "  Section header string table index: 38\n"
    )

    command = ExecutableHeaderCommand(RawExecutableHeader(raw_data))

    assert command.name() == "header"

    assert (
        command.output(["--validate"] if validated else []) == expected_output
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/corrupted-binary"], indirect=True
)
def test_executable_header_command_with_corrupted_binary_and_validate_flag(
    raw_data: bytearray,
) -> None:
    expected_error = (
        "Executable header contains invalid values:\n"
        "  e_type=5\n"
        "  e_flags=3735928559"
    )

    command = ExecutableHeaderCommand(RawExecutableHeader(raw_data))

    assert command.name() == "header"

    with pytest.raises(ValueError, match=re.escape(expected_error)):
        command.output(["--validate"])


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-32bit"], indirect=True
)
def test_executable_header_command_with_32_bit_binary(
    raw_data: bytearray,
) -> None:
    expected_error = "Binary must be 64-bit"

    command = ExecutableHeaderCommand(RawExecutableHeader(raw_data))

    assert command.name() == "header"

    with pytest.raises(ValueError, match=re.escape(expected_error)):
        command.output(["--validate"])


@pytest.mark.parametrize(
    "validated",
    [False, True],
)
@pytest.mark.parametrize(
    "raw_data",
    [
        "tests/samples/binaries/stripped-binary",
        "tests/samples/binaries/binary-with-stripped-section-headers",
    ],
    indirect=True,
)
def test_sections_command_with_validate_flag(
    raw_data: bytearray, capsys: CaptureFixture[str], validated: bool
) -> None:
    executable_header = RawExecutableHeader(raw_data)
    sections_headers = RawSectionHeaders(raw_data, executable_header)
    command = SectionsCommand(
        RawSections(
            raw_data,
            sections_headers,
            executable_header,
        ),
        sections_headers,
    )

    assert command.name() == "sections"

    output = command.output(["--validate"] if validated else [])

    assert re.match(
        r"^\s*Idx\s+Name\s+Type\s+Flags\s+Address"
        r"\s+Offset\s+Size\s+Link\s+Info\s+Align\s+ES",
        output,
    )
    assert re.search(
        r"^\[\d+]\s+"
        r"(?:\.\S+(?: \(\d+\))?|\(\d+\)|\d+|\s+)\s+"
        r"\d+\s+"
        r"0x[0-9a-fA-F]+\s+"
        r"0x[0-9a-fA-F]+\s+"
        r"0x[0-9a-fA-F]+\s+"
        r"\d+\s+"
        r"\d+\s+"
        r"\d+\s+"
        r"\d+\s+"
        r"\d+\s*$",
        output,
        re.MULTILINE,
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/corrupted-binary"], indirect=True
)
def test_sections_command_with_corrupted_binary_and_validate_flag(
    raw_data: bytearray,
) -> None:
    expected_error = (
        "Section header (27) contains invalid values:\n"
        "  sh_type=20\n"
        "  sh_flags=3735928559"
    )

    executable_header = RawExecutableHeader(raw_data)
    sections_headers = RawSectionHeaders(raw_data, executable_header)
    command = SectionsCommand(
        RawSections(
            raw_data,
            sections_headers,
            executable_header,
        ),
        sections_headers,
    )

    assert command.name() == "sections"

    with pytest.raises(ValueError, match=re.escape(expected_error)):
        command.output(["--validate"])


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_section_command(
    raw_data: bytearray, capsys: CaptureFixture[str]
) -> None:
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
        r"Section:\n\s+Name:\s+\.[\w\.]+",
        r"Data:\s+([0-9a-fA-F]{2} ?)+\.\.\.",
        r"ASCII:\s+.+\.\.\.",
    ]

    executable_header = RawExecutableHeader(raw_data)

    command = SectionCommand(
        RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        )
    )

    assert command.name() == "section"

    output = command.output(["--name", ".shstrtab"])

    for pattern in patterns:
        assert re.search(pattern, output) is not None


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_section_command_with_full_flag(
    raw_data: bytearray, capsys: CaptureFixture[str]
) -> None:
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
        r"Section:\n\s+Name:\s+\.[\w\.]+",
        r"Data:\s+([0-9a-fA-F]{2} ?)",
        r"ASCII:\s+.",
    ]

    executable_header = RawExecutableHeader(raw_data)

    output = SectionCommand(
        RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        )
    ).output(["--name", ".text", "--full"])

    for pattern in patterns:
        assert re.search(pattern, output) is not None


@pytest.mark.parametrize(
    "raw_data",
    ["tests/samples/binaries/binary-with-stripped-section-headers"],
    indirect=True,
)
def test_section_command_with_stripped_section_headers(
    raw_data: bytearray, capsys: CaptureFixture[str]
) -> None:
    expected_zero_sh_name = "0"
    expected_output = (
        "Section Header:\n"
        "  Name: 0\n"
        "  Type: 0\n"
        "  Flags: 0x0\n"
        "  Address: 0x0\n"
        "  Offset: 0x0\n"
        "  Section size: 0 bytes\n"
        "  Link: 0\n"
        "  Info: 0\n"
        "  Address alignment: 0\n"
        "  Section entry size: 0\n"
        "Section:\n"
        "  Name: 0\n"
        "  Data: ---\n"
        "  ASCII: ---\n"
    )

    executable_header = RawExecutableHeader(raw_data)

    command = SectionCommand(
        RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        )
    )

    assert command.name() == "section"

    assert command.output(["--name", expected_zero_sh_name]) == expected_output


@pytest.mark.parametrize(
    "raw_data",
    ["tests/samples/binaries/binary-with-stripped-section-headers"],
    indirect=True,
)
def test_section_command_with_stripped_section_headers_and_full_flag(
    raw_data: bytearray, capsys: CaptureFixture[str]
) -> None:
    expected_zero_sh_name = "0"
    expected_output = (
        "Section Header:\n"
        "  Name: 0\n"
        "  Type: 0\n"
        "  Flags: 0x0\n"
        "  Address: 0x0\n"
        "  Offset: 0x0\n"
        "  Section size: 0 bytes\n"
        "  Link: 0\n"
        "  Info: 0\n"
        "  Address alignment: 0\n"
        "  Section entry size: 0\n"
        "Section:\n"
        "  Name: 0\n"
        "  Data: ---\n"
        "  ASCII: ---\n"
    )

    executable_header = RawExecutableHeader(raw_data)

    command = SectionCommand(
        RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        )
    )

    assert command.name() == "section"

    assert (
        command.output(["--name", expected_zero_sh_name, "--full"])
        == expected_output
    )


@pytest.mark.parametrize(
    "validated",
    [False, True],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_symbol_table_command_with_all_flags(
    raw_data: bytearray, capsys: CaptureFixture[str], validated: bool
) -> None:
    executable_header = RawExecutableHeader(raw_data)

    command = DynsymCommand(
        RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        )
    )

    assert command.name() == "dynsym"

    output = command.output(["--validate"] if validated else [])

    assert re.match(
        r"^Symbol Table: \.\w+\nIdx\s+Value\s+Size\s+Bind\s+Type\s+"
        r"Visibility\s+Name",
        output,
    )
    assert re.search(
        r"^\[\d+\]\s+0x[0-9a-f]{16}\s+\d+\s+"
        r"(LOCAL|GLOBAL|WEAK)\s+"
        r"(NOTYPE|OBJECT|FUNC|SECTION|FILE|COMMON|TLS)\s+"
        r"(DEFAULT|INTERNAL|HIDDEN|PROTECTED)\s+"
        r"[\x20-\x7E]*$",
        output,
        re.MULTILINE,
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/corrupted-binary"], indirect=True
)
def test_dynsym_command_with_corrupted_binary_validate_flag(
    raw_data: bytearray,
) -> None:
    expected_error = (
        "Symbol (__libc_start_main) contains invalid values:\n  st_info=254"
    )

    executable_header = RawExecutableHeader(raw_data)

    command = DynsymCommand(
        RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        )
    )

    assert command.name() == "dynsym"

    with pytest.raises(ValueError, match=re.escape(expected_error)):
        command.output(["--validate"])


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/corrupted-binary"], indirect=True
)
def test_symtab_command_with_corrupted_binary_and_validate_flag(
    raw_data: bytearray,
) -> None:
    expected_error = "Symbol (Scrt1.o) contains invalid values:\n  st_info=254"

    executable_header = RawExecutableHeader(raw_data)

    command = SymtabCommand(
        RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        )
    )

    assert command.name() == "symtab"

    with pytest.raises(ValueError, match=re.escape(expected_error)):
        command.output(["--validate"])


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_text_command(
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
        "00001085: hlt"
    )

    executable_header = RawExecutableHeader(raw_data)

    command = TextCommand(
        RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        )
    )

    assert command.name() == "text"

    assert command.output([]).startswith(expected_output)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_plt_command(raw_data: bytearray, capsys: CaptureFixture[str]) -> None:
    expected_output = (
        "00001020: push qword ptr [rip + 0x2f72]\n"
        "00001026: bnd jmp qword ptr [rip + 0x2f73]\n"
        "0000102d: nop dword ptr [rax]\n"
        "00001030: endbr64\n"
        "00001034: push 0\n"
        "00001039: bnd jmp 0x1020\n"
        "0000103f: nop\n"
        "00001040: endbr64\n"
        "00001044: push 1\n"
        "00001049: bnd jmp 0x1020\n"
        "0000104f: nop"
    )

    executable_header = RawExecutableHeader(raw_data)

    command = PltCommand(
        RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        )
    )

    assert command.name() == "plt"

    assert command.output([]).startswith(expected_output)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_init_command(
    raw_data: bytearray, capsys: CaptureFixture[str]
) -> None:
    expected_output = (
        "00001000: endbr64\n"
        "00001004: sub rsp, 8\n"
        "00001008: mov rax, qword ptr [rip + 0x2fd9]\n"
        "0000100f: test rax, rax\n"
        "00001012: je 0x1016\n"
        "00001014: call rax\n"
        "00001016: add rsp, 8\n"
        "0000101a: ret"
    )

    executable_header = RawExecutableHeader(raw_data)

    command = InitCommand(
        RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        )
    )

    assert command.name() == "init"

    assert command.output([]) == expected_output


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_fini_command(
    raw_data: bytearray, capsys: CaptureFixture[str]
) -> None:
    expected_output = (
        "00001178: endbr64\n"
        "0000117c: sub rsp, 8\n"
        "00001180: add rsp, 8\n"
        "00001184: ret"
    )

    executable_header = RawExecutableHeader(raw_data)

    command = FiniCommand(
        RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        )
    )

    assert command.name() == "fini"

    assert command.output([]) == expected_output


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_invalid_argument(raw_data: bytearray) -> None:
    with pytest.raises(ValueError, match="Unrecognized arguments: --invalid"):
        executable_header = RawExecutableHeader(raw_data)

        SectionCommand(
            RawSections(
                raw_data,
                RawSectionHeaders(raw_data, executable_header),
                executable_header,
            )
        ).output(["--name", ".text", "--invalid"])


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_section_command_raising_on_nonexistent_section(
    raw_data: bytearray,
) -> None:
    with pytest.raises(ValueError, match="Section '.nonexistent' not found"):
        executable_header = RawExecutableHeader(raw_data)

        command = SectionCommand(
            RawSections(
                raw_data,
                RawSectionHeaders(raw_data, executable_header),
                executable_header,
            )
        )

        command.output(["--name", ".nonexistent"])


@pytest.mark.parametrize(
    "validated",
    [True, False],
)
@pytest.mark.parametrize(
    "raw_data",
    [
        "tests/samples/binaries/binary",
        "tests/samples/binaries/binary-2",
    ],
    indirect=True,
)
def test_segments_command_with_all_flags(
    raw_data: bytearray, capsys: CaptureFixture[str], validated: bool
) -> None:
    program_headers = RawProgramHeaders(
        raw_data, RawExecutableHeader(raw_data)
    )
    command = SegmentsCommand(
        RawSegments(
            raw_data,
            program_headers,
        ),
        program_headers,
    )

    assert command.name() == "segments"

    output = command.output(["--validate"] if validated else [])

    assert re.match(
        r"^\s*Idx\s+Type\s+Flags\s+Offset\s+VirtAddr\s+PhysAddr\s+"
        r"FileSize\s+MemSize\s+Align",
        output,
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
        output,
        re.MULTILINE,
    )


@pytest.mark.parametrize(
    "raw_data",
    ["tests/samples/binaries/corrupted-binary"],
    indirect=True,
)
def test_segments_command_with_corrupted_binary_and_validate_flag(
    raw_data: bytearray,
) -> None:
    expected_error = (
        "Program header (p_offset=792) contains invalid values:\n"
        "  p_type=4294967295\n"
        "  p_flags=3735928559"
    )

    program_headers = RawProgramHeaders(
        raw_data, RawExecutableHeader(raw_data)
    )
    command = SegmentsCommand(
        RawSegments(
            raw_data,
            program_headers,
        ),
        program_headers,
    )

    assert command.name() == "segments"

    with pytest.raises(ValueError, match=re.escape(expected_error)):
        command.output(["--validate"])


@pytest.mark.parametrize(
    "validated",
    [True, False],
)
@pytest.mark.parametrize(
    "raw_data",
    [
        "tests/samples/binaries/binary",
        "tests/samples/binaries/binary-2",
    ],
    indirect=True,
)
def test_dynamic_command(
    raw_data: bytearray, capsys: CaptureFixture[str], validated: bool
) -> None:
    command = DynamicCommand(
        RawSegments(
            raw_data,
            RawProgramHeaders(raw_data, RawExecutableHeader(raw_data)),
        )
    )

    assert command.name() == "dynamic"

    output = command.output(["--validate"] if validated else [])

    assert re.match(
        r"^\s*Idx\s+Tag\s+Value",
        output,
    )
    assert re.search(
        r"^\[\d+]\s+(DT_\w+|0x[0-9a-f]{8})\s+\d+$",
        output,
        re.MULTILINE,
    )


@pytest.mark.parametrize(
    "raw_data",
    ["tests/samples/binaries/corrupted-binary"],
    indirect=True,
)
def test_dynamic_command_with_corrupted_binary_and_validate_flag(
    raw_data: bytearray,
) -> None:
    expected_error = "Dynamic entry contains invalid values:\n  d_tag=123"

    command = DynamicCommand(
        RawSegments(
            raw_data,
            RawProgramHeaders(raw_data, RawExecutableHeader(raw_data)),
        )
    )

    assert command.name() == "dynamic"

    with pytest.raises(ValueError, match=re.escape(expected_error)):
        command.output(["--validate"])
