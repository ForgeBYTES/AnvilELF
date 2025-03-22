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
