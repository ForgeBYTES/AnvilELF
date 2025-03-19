import os
import stat

import pytest
from pytest_mock import MockerFixture

from src.elf.executable_header import RawExecutableHeader
from src.elf.section_header import (
    RawSectionHeader,
    RawSectionHeaders,
    SectionHeader,
    ValidatedSectionHeader,
    ValidatedSectionHeaders,
)
from tests.fixtures.fixtures import TemporaryFiles


@pytest.fixture
def expected_data():
    return {
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


@pytest.fixture
def prepare_temporary_binaries():
    files = TemporaryFiles(
        original_path="tests/samples/binaries",
        temporary_path="tests/samples/temporary_binaries",
    )

    files.copy()

    yield

    files.unlink()


@pytest.mark.parametrize(
    "_class",
    [
        RawSectionHeader,
        lambda filename, offset: ValidatedSectionHeader(
            RawSectionHeader(
                filename=filename,
                offset=offset,
            )
        ),
    ],
)
def test_returning_fields_by_providing_filename_and_offset(
    expected_data, _class
):
    filename = "tests/samples/binaries/binary"
    offset = RawExecutableHeader(filename).fields()["e_shoff"]

    fields = _class(
        filename=filename,
        offset=offset + 64,
    ).fields()

    assert fields == expected_data


@pytest.mark.parametrize(
    "_class",
    [
        RawSectionHeader,
        lambda filename, offset: ValidatedSectionHeader(
            RawSectionHeader(
                filename=filename,
                offset=offset,
            )
        ),
    ],
)
def test_changing_fields(prepare_temporary_binaries, expected_data, _class):
    filename = "tests/samples/temporary_binaries/binary"
    offset = RawExecutableHeader(filename).fields()["e_shoff"]

    original_sh_flags = 2
    expected_sh_flags = 4

    section_header = _class(
        filename=filename,
        offset=offset + 64,
    )

    assert section_header.fields()["sh_flags"] == original_sh_flags

    expected_data["sh_flags"] = expected_sh_flags

    section_header.change(expected_data)

    assert section_header.fields() == expected_data


def test_raising_on_changing_fields_with_missing_key_in_expected_data(
    prepare_temporary_binaries, expected_data
):
    filename = "tests/samples/temporary_binaries/binary"
    offset = RawExecutableHeader(filename).fields()["e_shoff"]

    expected_data["sh_flags"] = 4

    del expected_data["sh_addr"]

    with pytest.raises(ValueError, match="Unable to process data"):
        RawSectionHeader(filename=filename, offset=offset + 64).change(
            expected_data
        )


def test_raising_on_returning_fields_of_unprocessable_binary(
    mocker: MockerFixture,
):
    mocker.patch(
        "builtins.open", mocker.mock_open(read_data=b"unprocessable content")
    )

    with pytest.raises(ValueError, match="Unable to process data"):
        RawSectionHeader(
            filename="path/to/unprocessable_binary", offset=5
        ).fields()


def test_raising_on_changing_field_with_unprocessable_data_type(
    prepare_temporary_binaries,
    expected_data,
):
    filename = "tests/samples/temporary_binaries/binary"
    offset = RawExecutableHeader(filename).fields()["e_shoff"]

    expected_data["sh_flags"] = "unprocessable data type"

    with pytest.raises(ValueError, match="Unable to process data"):
        RawSectionHeader(
            filename=filename,
            offset=offset + 64,
        ).change(expected_data)


def test_raising_on_returning_fields_when_missing_filename_or_offset():
    filename = "tests/samples/binaries/binary"
    offset = 13984

    with pytest.raises(
        ValueError, match="Filename and offset must be provided"
    ):
        RawSectionHeader(filename=filename).fields()
    with pytest.raises(
        ValueError, match="Filename and offset must be provided"
    ):
        RawSectionHeader(offset=offset + 64).fields()
    with pytest.raises(
        ValueError, match="Filename and offset must be provided"
    ):
        RawSectionHeader().fields()


def test_raising_on_changing_field_when_missing_filename_or_offset(
    expected_data,
):
    filename = "tests/samples/binaries/binary"
    offset = 13984

    expected_data["sh_flags"] = 4

    with pytest.raises(
        ValueError, match="Filename and offset must be provided"
    ):
        RawSectionHeader(filename=filename).change(expected_data)
    with pytest.raises(
        ValueError, match="Filename and offset must be provided"
    ):
        RawSectionHeader(offset=offset + 64).change(expected_data)
    with pytest.raises(
        ValueError, match="Filename and offset must be provided"
    ):
        RawSectionHeader().change(expected_data)


def test_raising_on_returning_fields_using_nonexistent_filename():
    with pytest.raises(ValueError, match="Failed to read file"):
        RawSectionHeader(filename="nonexistent", offset=13984).fields()


def test_raising_on_changing_field_using_readonly_binary(
    prepare_temporary_binaries,
    expected_data,
):
    filename = "tests/samples/temporary_binaries/binary"
    os.chmod(filename, stat.S_IREAD)

    expected_data["sh_flags"] = 4

    with pytest.raises(ValueError, match="Failed to write to file"):
        RawSectionHeader(filename=filename, offset=13984).change(expected_data)


def test_returning_all_section_headers():
    filename = "tests/samples/binaries/binary"

    executable_header = RawExecutableHeader(filename)
    section_headers = RawSectionHeaders(executable_header).all()

    assert len(section_headers) == executable_header.fields()["e_shnum"]
    assert all(
        isinstance(section_header, SectionHeader)
        for section_header in section_headers
    )


def test_raising_on_nonexistent_executable_header_filename():
    with pytest.raises(ValueError, match="Failed to read file"):
        RawSectionHeaders(RawExecutableHeader("nonexistent")).all()


@pytest.mark.parametrize(
    "field, value, error_message",
    [
        ("sh_type", 20, "Invalid value for sh_type"),
        ("sh_flags", 0xDEADBEEF, "Invalid value for sh_flags"),
        ("sh_addralign", 3, "Invalid value for sh_addralign"),
        ("sh_size", -1, "Invalid value for sh_size"),
        ("sh_offset", -1, "Invalid value for sh_offset"),
        ("invalid", 2, "Unknown field invalid"),
    ],
)
def test_raising_on_changing_invalid_field_values(
    prepare_temporary_binaries, expected_data, field, value, error_message
):
    filename = "tests/samples/temporary_binaries/binary"
    offset = RawExecutableHeader(filename).fields()["e_shoff"]

    expected_data[field] = value

    with pytest.raises(ValueError, match=error_message):
        ValidatedSectionHeader(
            RawSectionHeader(filename=filename, offset=offset + 64)
        ).change(expected_data)


@pytest.mark.parametrize(
    "sh_flags, sh_addr, sh_addralign, should_pass",
    [
        (0x2, 0x1000, 8, True),
        (0x2, 0x1003, 8, False),
        (0x2, 0x1000, 1, True),
        (0x2, 0x1000, 0, True),
        (0x0, 0x1003, 8, True),
    ],
)
def test_changing_sh_addr_alignment(
    prepare_temporary_binaries,
    expected_data,
    sh_flags,
    sh_addr,
    sh_addralign,
    should_pass,
):
    filename = "tests/samples/temporary_binaries/binary"
    offset = RawExecutableHeader(filename).fields()["e_shoff"]

    section_header = ValidatedSectionHeader(
        RawSectionHeader(filename=filename, offset=offset + 64)
    )

    expected_data["sh_flags"] = sh_flags
    expected_data["sh_addr"] = sh_addr
    expected_data["sh_addralign"] = sh_addralign

    if should_pass:
        section_header.change(expected_data)
    else:
        with pytest.raises(ValueError, match="Invalid value for sh_addr"):
            section_header.change(expected_data)


def test_returning_all_validated_section_headers_and_their_fields():
    expected_fields = [
        "sh_name",
        "sh_type",
        "sh_flags",
        "sh_addr",
        "sh_offset",
        "sh_size",
        "sh_link",
        "sh_info",
        "sh_addralign",
        "sh_entsize",
    ]

    filename = "tests/samples/binaries/binary"

    executable_header = RawExecutableHeader(filename)
    section_headers = ValidatedSectionHeaders(
        RawSectionHeaders(executable_header)
    ).all()

    assert len(section_headers) == executable_header.fields()["e_shnum"]
    assert all(
        isinstance(section_header, ValidatedSectionHeader)
        for section_header in section_headers
    )

    for section_header in section_headers:
        assert list(section_header.fields().keys()) == expected_fields
