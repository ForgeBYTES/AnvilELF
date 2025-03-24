import pytest

from src.elf.executable_header import RawExecutableHeader
from src.elf.section import RawSection, RawSections
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
def test_returning_name_offset_if_string_table_is_not_present(raw_data):
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
        "  Offset: 18835\n"
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
        "  Offset: 12347\n"
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
