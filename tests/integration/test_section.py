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
    with open(request.param, "rb") as binary:
        return bytearray(binary.read())


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
def test_raising_on_returning_section_by_nonexistent_name(raw_data):
    executable_header = RawExecutableHeader(raw_data)

    with pytest.raises(ValueError, match="Section '.nonexistent' not found"):
        assert RawSections(
            raw_data,
            RawSectionHeaders(raw_data, executable_header),
            executable_header,
        ).by_name(".nonexistent")


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
        "Section header table:\n"
        "  [0x01] .symtab\n"
        "  [0x09] .strtab\n"
        "  [0x11] .shstrtab\n"
        "  [0x1b] .interp\n"
        "  [0x23] .note.gnu.property\n"
        "  [0x36] .note.gnu.build-id\n"
        "  [0x49] .note.ABI-tag\n"
        "  [0x57] .gnu.hash\n"
        "  [0x61] .dynsym\n"
        "  [0x69] .dynstr\n"
        "  [0x71] .gnu.version\n"
        "  [0x7e] .gnu.version_r\n"
        "  [0x8d] .rela.dyn\n"
        "  [0x97] .rela.plt\n"
        "  [0xa1] .init\n"
        "  [0xa7] .plt.got\n"
        "  [0xb0] .plt.sec\n"
        "  [0xb9] .text\n"
        "  [0xbf] .fini\n"
        "  [0xc5] .rodata\n"
        "  [0xcd] .eh_frame_hdr\n"
        "  [0xdb] .eh_frame\n"
        "  [0xe5] .init_array\n"
        "  [0xf1] .fini_array\n"
        "  [0xfd] .dynamic\n"
        "  [0x106] .data\n"
        "  [0x10c] .bss\n"
        "  [0x111] .comment\n"
        "  [0x11a] .debug_aranges\n"
        "  [0x129] .debug_info\n"
        "  [0x135] .debug_abbrev\n"
        "  [0x143] .debug_line\n"
        "  [0x14f] .debug_str\n"
        "  [0x15a] .debug_line_str\n"
        "  [0x16a] .debug_loclists\n"
        "  [0x17a] .debug_rnglists"
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
def test_string_representation_of_shstrtab_on_stripped_binary(raw_data):
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
        "Section header table:\n"
        "  [0x01] .shstrtab\n"
        "  [0x0b] .interp\n"
        "  [0x13] .note.gnu.property\n"
        "  [0x26] .note.gnu.build-id\n"
        "  [0x39] .note.ABI-tag\n"
        "  [0x47] .gnu.hash\n  [0x51] .dynsym\n"
        "  [0x59] .dynstr\n"
        "  [0x61] .gnu.version\n"
        "  [0x6e] .gnu.version_r\n"
        "  [0x7d] .rela.dyn\n"
        "  [0x87] .rela.plt\n"
        "  [0x91] .init\n"
        "  [0x97] .plt.got\n"
        "  [0xa0] .plt.sec\n"
        "  [0xa9] .text\n"
        "  [0xaf] .fini\n"
        "  [0xb5] .rodata\n"
        "  [0xbd] .eh_frame_hdr\n"
        "  [0xcb] .eh_frame\n"
        "  [0xd5] .init_array\n"
        "  [0xe1] .fini_array\n"
        "  [0xed] .dynamic\n"
        "  [0xf6] .data\n"
        "  [0xfc] .bss\n"
        "  [0x101] .comment"
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
        "Section Header:\n"
        "  Name: 185 (index in .shstrtab)\n"
        "  Type: 1\n"
        "  Flags: 0x6\n"
        "  Address: 0x1060\n"
        "  Offset: 0x1060\n"
        "  Section size: 279 bytes\n"
        "  Link: 0\n"
        "  Info: 0\n"
        "  Address alignment: 16\n"
        "  Section entry size: 0\n"
        "Section:\n"
        "  Name: .text\n"
        "  Data: f3 0f 1e fa 31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 45 "
        "31 c0 31 c9 48 8d 3d ca 00 00 00 ff ...\n"
        "  ASCII: ....1.I..^H..H...PTE1.1.H.=..... ...\n"
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
