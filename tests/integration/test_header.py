import pytest
from pytest_mock import MockerFixture

from src.elf.header import ExecutableHeader


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

    fields = ExecutableHeader(BINARY_PATH).fields()

    assert fields["e_ident"] == EXPECTED_OUTPUT["e_ident"]
    assert fields["e_type"] == EXPECTED_OUTPUT["e_type"]
    assert fields["e_machine"] == EXPECTED_OUTPUT["e_machine"]
    assert fields["e_version"] == EXPECTED_OUTPUT["e_version"]


def test_raising_on_nonexistent_elf_binary_path():
    with pytest.raises(ValueError, match="Could not open the file"):
        ExecutableHeader("nonexistent").fields()


def test_raising_on_unprocessable_file(mocker: MockerFixture):
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"unprocessable"))

    with pytest.raises(ValueError, match="Unable to process ELF binary"):
        ExecutableHeader("invalid").fields()


def test_raising_on_elf_binary_with_malformed_ei_data():
    BINARY_PATH = "tests/samples/binaries/binary-with-malformed-ei-data"

    with pytest.raises(ValueError, match="ELF binary is not valid"):
        ExecutableHeader(BINARY_PATH).fields()


def test_raising_on_elf_binary_with_malformed_ei_version():
    BINARY_PATH = "tests/samples/binaries/binary-with-malformed-ei-version"

    with pytest.raises(ValueError, match="ELF binary is not valid"):
        ExecutableHeader(BINARY_PATH).fields()


def test_raising_on_elf_binary_with_malformed_e_type():
    BINARY_PATH = "tests/samples/binaries/binary-with-malformed-e-type"

    with pytest.raises(ValueError, match="ELF binary is not valid"):
        ExecutableHeader(BINARY_PATH).fields()


def test_raising_on_32bit_elf_binary():
    BINARY_PATH = "tests/samples/binaries/binary-32bit"

    with pytest.raises(ValueError, match="ELF binary must be 64-bit"):
        ExecutableHeader(BINARY_PATH).fields()
