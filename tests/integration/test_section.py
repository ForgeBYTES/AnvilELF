from typing import cast

import pytest

from src.elf.executable_header import RawExecutableHeader
from src.elf.section import (
    RawSection,
    RawSections,
    RawShstrtabSection,
    RawTextSection,
)
from src.elf.section_header import RawSectionHeader, RawSectionHeaders


@pytest.fixture
def raw_data(request) -> bytearray:
    with open(request.param, "rb") as f:
        return bytearray(f.read())


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_section_names(raw_data):
    # fmt: off
    expected_section_names = [
        "", ".interp", ".note.gnu.property", ".note.gnu.build-id",
        ".note.ABI-tag", ".gnu.hash", ".dynsym", ".dynstr",
        ".gnu.version", ".gnu.version_r", ".rela.dyn", ".rela.plt",
        ".init", ".plt", ".plt.got", ".plt.sec",
        ".text", ".fini", ".rodata", ".eh_frame_hdr",
        ".eh_frame", ".init_array", ".fini_array", ".dynamic",
        ".got", ".data", ".bss", ".comment",
        ".symtab", ".strtab", ".shstrtab",
    ]
    # fmt: on

    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    ).all()

    assert [section.name() for section in sections] == expected_section_names


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_sections_by_name(raw_data):
    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    assert sections.by_name(".text").name() == ".text"
    assert sections.by_name(".shstrtab").name() == ".shstrtab"


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_name_offset_if_shstrtab_is_not_present(raw_data):
    expected_string_offset = "27"

    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    assert (
        RawSection(raw_data, RawSectionHeader(raw_data, offset + 64)).name()
        == expected_string_offset
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_string_representation(raw_data):
    expected_string = (
        "Section Header:\n"
        "  Name: 17 (index in .shstrtab)\n"
        "  Type: 3\n"
        "  Flags: 0x0\n"
        "  Address: 0x0\n"
        "  Offset: 0x4993\n"
        "  Section size: 394 bytes\n"
        "  Link: 0\n"
        "  Info: 0\n"
        "  Address alignment: 1\n"
        "  Section entry size: 0\n"
        "Section:\n"
        "  Name: .shstrtab\n"
        "  Data: 00 2e 73 79 6d 74 61 62 00 2e 73 74 72 74 61 62 00 2e 73 68 "
        "73 74 72 74 61 62 00 2e 69 6e 74 65 ...\n"
        "  ASCII: ..symtab..strtab..shstrtab..inte ...\n"
    )

    executable_header = RawExecutableHeader(raw_data)
    e_shstrndx = executable_header.fields()["e_shstrndx"]

    shstrtab = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    ).all()[e_shstrndx]

    assert str(shstrtab) == expected_string


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_string_representation_on_stripped_binary(raw_data):
    expected_string = (
        "Section Header:\n"
        "  Name: 1 (index in .shstrtab)\n"
        "  Type: 3\n"
        "  Flags: 0x0\n"
        "  Address: 0x0\n"
        "  Offset: 0x303b\n"
        "  Section size: 266 bytes\n"
        "  Link: 0\n"
        "  Info: 0\n"
        "  Address alignment: 1\n"
        "  Section entry size: 0\n"
        "Section:\n"
        "  Name: .shstrtab\n"
        "  Data: 00 2e 73 68 73 74 72 74 61 62 00 2e 69 6e 74 65 72 70 00 2e "
        "6e 6f 74 65 2e 67 6e 75 2e 70 72 6f ...\n"
        "  ASCII: ..shstrtab..interp..note.gnu.pro ...\n"
    )

    executable_header = RawExecutableHeader(raw_data)
    e_shstrndx = executable_header.fields()["e_shstrndx"]

    shstrtab = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    ).all()[e_shstrndx]

    assert str(shstrtab) == expected_string


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_shstrtab_name_by_index_and_vice_versa(raw_data):
    executable_header = RawExecutableHeader(raw_data)
    section_headers = RawSectionHeaders(raw_data, executable_header)

    shstrtab = RawShstrtabSection(
        RawSection(
            raw_data,
            section_headers.all()[executable_header.fields()["e_shstrndx"]],
        )
    )
    assert shstrtab.index_by_name(".shstrtab") == 17
    assert shstrtab.name_by_index(17) == ".shstrtab"


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_bss_section_by_name(raw_data):
    executable_header = RawExecutableHeader(raw_data)

    bss = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    ).by_name(".bss")

    assert bss.name() == ".bss"


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_returning_shstrtab_index_with_nonexistent_name(
    raw_data,
):
    executable_header = RawExecutableHeader(raw_data)
    section_headers = RawSectionHeaders(raw_data, executable_header)

    with pytest.raises(
        ValueError, match="Section name '.nonexistent' not found in .shstrtab"
    ):
        shstrtab = RawShstrtabSection(
            RawSection(
                raw_data,
                section_headers.all()[
                    executable_header.fields()["e_shstrndx"]
                ],
            )
        )
        shstrtab.index_by_name(".nonexistent")


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_text_disassembly_string_representation(raw_data):
    expected_output = (
        "Disassembly:\n"
        "  00001060: endbr64 \n"
        "  00001064: xor ebp, ebp\n"
        "  00001066: mov r9, rdx\n"
        "  00001069: pop rsi\n"
        "  0000106a: mov rdx, rsp\n"
        "  0000106d: and rsp, 0xfffffffffffffff0\n"
        "  00001071: push rax\n"
        "  00001072: push rsp\n"
        "  00001073: xor r8d, r8d\n"
        "  00001076: xor ecx, ecx\n"
        "  00001078: lea rdi, [rip + 0xca]\n"
        "  0000107f: call qword ptr [rip + 0x2f53]\n"
        "  00001085: hlt \n"
    )

    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    text = cast(RawTextSection, sections.by_name(".text"))

    assert str(text).startswith(expected_output)
