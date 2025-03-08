import shutil
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from src.elf.header import RawExecutableHeader


@pytest.fixture
def prepare_temporary_binaries():
    temporary_directory = Path("tests/samples/temporary_binaries")

    for file in Path("tests/samples/binaries").iterdir():
        if file.is_file():
            shutil.copy(file, temporary_directory)

    yield

    for file in temporary_directory.iterdir():
        if file.name != ".gitkeep":
            file.unlink()


def test_returning_valid_executable_header():
    BINARY_PATH = "tests/samples/binaries/binary"
    EXPECTED_OUTPUT = {
        "e_ident": {
            "EI_MAG": b"\x7fELF",
            "EI_CLASS": 2,
            "EI_DATA": 1,
            "EI_VERSION": 1,
            "EI_OSABI": 0,
            "EI_ABIVERSION": 0,
            "EI_PAD": b"\x00" * 7,
        },
        "e_type": 3,
        "e_machine": 62,
        "e_version": 1,
    }

    fields = RawExecutableHeader(BINARY_PATH).fields()

    assert fields["e_ident"] == EXPECTED_OUTPUT["e_ident"]
    assert fields["e_type"] == EXPECTED_OUTPUT["e_type"]
    assert fields["e_machine"] == EXPECTED_OUTPUT["e_machine"]
    assert fields["e_version"] == EXPECTED_OUTPUT["e_version"]


def test_changing_single_field_in_executable_header(
    prepare_temporary_binaries,
):
    BINARY_PATH = "tests/samples/temporary_binaries/binary"

    ORIGINAL_EI_DATA = 1
    EXPECTED_EI_DATA = 2

    executable_header = RawExecutableHeader(BINARY_PATH)

    assert executable_header.fields()["e_ident"]["EI_DATA"] == ORIGINAL_EI_DATA

    executable_header.change({"e_ident": {"EI_DATA": EXPECTED_EI_DATA}})

    assert executable_header.fields()["e_ident"]["EI_DATA"] == EXPECTED_EI_DATA


def test_changing_multiple_fields_in_executable_header(
    prepare_temporary_binaries,
):
    BINARY_PATH = "tests/samples/temporary_binaries/binary"

    ORIGINAL_EI_DATA = 1
    ORIGINAL_E_TYPE = 3

    EXPECTED_EI_DATA = 2
    EXPECTED_E_TYPE = 1

    executable_header = RawExecutableHeader(BINARY_PATH)

    assert executable_header.fields()["e_ident"]["EI_DATA"] == ORIGINAL_EI_DATA
    assert executable_header.fields()["e_type"] == ORIGINAL_E_TYPE

    executable_header.change(
        {
            "e_ident": {"EI_DATA": EXPECTED_EI_DATA},
            "e_type": EXPECTED_E_TYPE,
        }
    )

    assert executable_header.fields()["e_ident"]["EI_DATA"] == EXPECTED_EI_DATA
    assert executable_header.fields()["e_type"] == EXPECTED_E_TYPE


def test_raising_on_nonexistent_elf_binary_path():
    with pytest.raises(ValueError, match="Failed to read ELF file"):
        RawExecutableHeader("nonexistent").fields()


def test_raising_on_unprocessable_file(mocker: MockerFixture):
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"unprocessable"))

    with pytest.raises(ValueError, match="Unable to process ELF file"):
        RawExecutableHeader("invalid").fields()


def test_raising_on_elf_binary_with_malformed_ei_data():
    BINARY_PATH = "tests/samples/binaries/binary-with-malformed-ei-data"

    with pytest.raises(ValueError, match="ELF file is not valid"):
        RawExecutableHeader(BINARY_PATH).fields()


def test_raising_on_elf_binary_with_malformed_ei_version():
    BINARY_PATH = "tests/samples/binaries/binary-with-malformed-ei-version"

    with pytest.raises(ValueError, match="ELF file is not valid"):
        RawExecutableHeader(BINARY_PATH).fields()


def test_raising_on_elf_binary_with_malformed_e_type():
    BINARY_PATH = "tests/samples/binaries/binary-with-malformed-e-type"

    with pytest.raises(ValueError, match="ELF file is not valid"):
        RawExecutableHeader(BINARY_PATH).fields()


def test_raising_on_32bit_elf_binary():
    BINARY_PATH = "tests/samples/binaries/binary-32bit"

    with pytest.raises(ValueError, match="ELF file must be 64-bit"):
        RawExecutableHeader(BINARY_PATH).fields()
