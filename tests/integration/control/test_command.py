import re

import pytest

from src.control.command import (
    ExecutableHeaderCommand,
    FiniCommand,
    InitCommand,
    PltCommand,
    SectionCommand,
    SectionsCommand,
    TextCommand,
)
from src.elf.executable_header import RawExecutableHeader
from src.elf.section import RawSections
from src.elf.section_header import RawSectionHeaders


@pytest.fixture
def raw_data(request) -> bytearray:
    with open(request.param, "rb") as binary:
        return bytearray(binary.read())


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_executable_header_command(raw_data, capsys):
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

    command = ExecutableHeaderCommand(RawExecutableHeader(raw_data))

    assert command.name() == "header"

    command.execute([])

    assert capsys.readouterr().out == expected_output


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_sections_command_with_full_flag(raw_data, capsys):
    executable_header = RawExecutableHeader(raw_data)

    command = SectionsCommand(
        RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        )
    )

    assert command.name() == "sections"

    command.execute(["--full"])

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
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_section_command(raw_data, capsys):
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

    command.execute(["--name", ".shstrtab"])
    output = capsys.readouterr().out

    for pattern in patterns:
        assert re.search(pattern, output) is not None


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_section_command_with_full_flag(raw_data, capsys):
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
        r"Section:\n\s+Name:\s+\.[\w\.]+",
        r"Data:\s+([0-9a-fA-F]{2} ?)",
        r"ASCII:\s+.",
    ]

    executable_header = RawExecutableHeader(raw_data)

    SectionCommand(
        RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        )
    ).execute(["--name", ".text", "--full"])

    output = capsys.readouterr().out

    for pattern in patterns:
        assert re.search(pattern, output) is not None


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_text_command(raw_data, capsys):
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

    command = TextCommand(
        RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        )
    )

    assert command.name() == "text"

    command.execute([])

    assert capsys.readouterr().out.startswith(expected_output)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_plt_command(raw_data, capsys):
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
        "0000104f: nop\n"
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

    command.execute([])

    assert capsys.readouterr().out.startswith(expected_output)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_init_command(raw_data, capsys):
    expected_output = (
        "00001000: endbr64\n"
        "00001004: sub rsp, 8\n"
        "00001008: mov rax, qword ptr [rip + 0x2fd9]\n"
        "0000100f: test rax, rax\n"
        "00001012: je 0x1016\n"
        "00001014: call rax\n"
        "00001016: add rsp, 8\n"
        "0000101a: ret\n"
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

    command.execute([])

    assert capsys.readouterr().out == expected_output


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_fini_command(raw_data, capsys):
    expected_output = (
        "00001178: endbr64\n"
        "0000117c: sub rsp, 8\n"
        "00001180: add rsp, 8\n"
        "00001184: ret\n"
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

    command.execute([])

    assert capsys.readouterr().out == expected_output


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_invalid_argument(raw_data):
    with pytest.raises(ValueError, match="Invalid arguments: "):
        executable_header = RawExecutableHeader(raw_data)

        SectionCommand(
            RawSections(
                raw_data,
                RawSectionHeaders(raw_data, executable_header),
                executable_header,
            )
        ).execute(["--name", ".text", "--invalid"])


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_section_command_raising_on_nonexistent_section(raw_data):
    with pytest.raises(ValueError, match="Section '.nonexistent' not found"):
        executable_header = RawExecutableHeader(raw_data)

        command = SectionCommand(
            RawSections(
                raw_data,
                RawSectionHeaders(raw_data, executable_header),
                executable_header,
            )
        )

        command.execute(["--name", ".nonexistent"])
