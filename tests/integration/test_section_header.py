import pytest

from src.elf.executable_header import RawExecutableHeader
from src.elf.section_header import (
    RawSectionHeader,
    RawSectionHeaders,
    SectionHeader,
)
from tests.fixtures.fixtures import TemporaryFiles


@pytest.fixture
def prepare_temporary_binaries():
    files = TemporaryFiles(
        original_path="tests/samples/binaries",
        temporary_path="tests/samples/temporary_binaries",
    )

    files.copy()

    yield

    files.unlink()


def test_returning_fields_by_providing_filename_and_offset():
    expected_fields = {
        "sh_name": 27,
        "sh_type": 1,
        "sh_flags": 2,
        "sh_addr": 792,
        "sh_offset": 792,
        "sh_size": 28,
        "sh_link": 0,
        "sh_info": 0,
        "sh_addralign": 1,
        "sh_entsize": 0,
    }
    binary_path = "tests/samples/binaries/binary"
    offset = RawExecutableHeader(binary_path).fields()["e_shoff"]

    fields = RawSectionHeader(
        filename=binary_path,
        offset=offset + 64,
    ).fields()

    assert fields == expected_fields


def test_changing_sh_flags(prepare_temporary_binaries):
    original_sh_flags = 2
    expected_sh_flags = 4
    expected_fields = {
        "sh_name": 27,
        "sh_type": 1,
        "sh_flags": expected_sh_flags,
        "sh_addr": 792,
        "sh_offset": 792,
        "sh_size": 28,
        "sh_link": 0,
        "sh_info": 0,
        "sh_addralign": 1,
        "sh_entsize": 0,
    }

    binary_path = "tests/samples/temporary_binaries/binary"
    offset = RawExecutableHeader(binary_path).fields()["e_shoff"]

    section_header = RawSectionHeader(
        filename=binary_path,
        offset=offset + 64,
    )

    assert section_header.fields()["sh_flags"] == original_sh_flags

    section_header.change({"sh_flags": expected_sh_flags})

    assert section_header.fields() == expected_fields


def test_raising_on_missing_filename_or_offset():
    binary_path = "tests/samples/binaries/binary"
    offset = 13984

    with pytest.raises(
        ValueError, match="Filename and offset must be provided"
    ):
        RawSectionHeader(filename=binary_path).fields()

    with pytest.raises(
        ValueError, match="Filename and offset must be provided"
    ):
        RawSectionHeader(offset=offset + 64).fields()

    with pytest.raises(
        ValueError, match="Filename and offset must be provided"
    ):
        RawSectionHeader().fields()


def test_raising_on_nonexistent_filename():
    with pytest.raises(ValueError, match="Failed to read file"):
        RawSectionHeader(filename="nonexistent", offset=13984).fields()


def test_returning_all_section_headers():
    binary_path = "tests/samples/binaries/binary"

    executable_header = RawExecutableHeader(binary_path)
    section_headers = RawSectionHeaders(executable_header).all()

    assert len(section_headers) == executable_header.fields()["e_shnum"]
    assert all(isinstance(header, SectionHeader) for header in section_headers)


def test_raising_on_nonexistent_executable_header_filename():
    with pytest.raises(ValueError, match="Failed to read file"):
        RawSectionHeaders(RawExecutableHeader("nonexistent")).all()
