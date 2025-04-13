import pytest

from src.elf.executable_header import (
    CachedExecutableHeader,
    RawExecutableHeader,
)
from src.elf.section import (
    CachedSections,
    DisassembledSection,
    RawSection,
    RawSections,
    RawShstrtabSection,
)
from src.elf.section_header import (
    CachedSectionHeaders,
    RawSectionHeader,
    RawSectionHeaders,
)


@pytest.fixture
def raw_data(request) -> bytearray:
    with open(request.param, "rb") as binary:
        return bytearray(binary.read())


@pytest.mark.parametrize(
    "sections",
    [
        lambda raw_data: RawSections(
            raw_data,
            RawSectionHeaders(raw_data, RawExecutableHeader(raw_data)),
            RawExecutableHeader(raw_data),
        ),
        lambda raw_data: CachedSections(
            raw_data,
            CachedSectionHeaders(
                RawSectionHeaders(raw_data, RawExecutableHeader(raw_data))
            ),
            CachedExecutableHeader(RawExecutableHeader(raw_data)),
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_returning_section_names(raw_data, sections):
    # fmt: off
    expected_section_names = [
        "", ".interp", ".note.gnu.property", ".note.gnu.build-id",
        ".note.ABI-tag", ".gnu.hash", ".dynsym", ".dynstr",
        ".gnu.version", ".gnu.version_r", ".rela.dyn", ".rela.plt",
        ".init", ".plt", ".plt.got", ".plt.sec",
        ".text", ".fini", ".rodata", ".eh_frame_hdr",
        ".eh_frame", ".init_array", ".fini_array", ".dynamic",
        ".got", ".data", ".bss", ".comment", ".debug_aranges",
        ".debug_info", ".debug_abbrev", ".debug_line", ".debug_str",
        ".debug_line_str", ".debug_loclists", ".debug_rnglists", ".symtab",
        ".strtab", ".shstrtab",
    ]
    # fmt: on
    assert [
        section.name() for section in sections(raw_data).all()
    ] == expected_section_names


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_returning_section_names_on_stripped_binary(raw_data):
    # fmt: off
    expected_section_names = [
        "", ".interp", ".note.gnu.property", ".note.gnu.build-id",
        ".note.ABI-tag", ".gnu.hash", ".dynsym", ".dynstr",
        ".gnu.version", ".gnu.version_r", ".rela.dyn", ".rela.plt",
        ".init", ".plt", ".plt.got", ".plt.sec",
        ".text", ".fini", ".rodata", ".eh_frame_hdr",
        ".eh_frame", ".init_array", ".fini_array", ".dynamic",
        ".got", ".data", ".bss", ".comment", ".shstrtab",
    ]
    # fmt: on

    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, RawExecutableHeader(raw_data)),
        RawExecutableHeader(raw_data),
    )

    assert [
        section.name() for section in sections.all()
    ] == expected_section_names


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
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_shstrtab_name_by_index(raw_data):
    executable_header = RawExecutableHeader(raw_data)
    section_headers = RawSectionHeaders(raw_data, executable_header)

    shstrtab = RawShstrtabSection(
        RawSection(
            raw_data,
            section_headers.all()[executable_header.fields()["e_shstrndx"]],
        )
    )
    assert shstrtab.name_by_index(17) == ".shstrtab"


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_text_disassembly(raw_data):
    expected_output = [
        "00001060: endbr64",
        "00001064: xor ebp, ebp",
        "00001066: mov r9, rdx",
        "00001069: pop rsi",
        "0000106a: mov rdx, rsp",
        "0000106d: and rsp, 0xfffffffffffffff0",
        "00001071: push rax",
        "00001072: push rsp",
        "00001073: xor r8d, r8d",
        "00001076: xor ecx, ecx",
        "00001078: lea rdi, [rip + 0xca]",
        "0000107f: call qword ptr [rip + 0x2f53]",
        "00001085: hlt",
    ]

    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    for section in sections.all():
        if section.name() == ".text":
            assert (
                DisassembledSection(section).disassembly()[
                    : len(expected_output)
                ]
                == expected_output
            )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_disassembling_not_executable_section(raw_data):
    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    bss = next(
        section for section in sections.all() if section.name() == ".bss"
    )

    assert bss is not None

    with pytest.raises(ValueError, match="Section is not executable"):
        DisassembledSection(bss).disassembly()
