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
    assert isinstance(fields["e_entry"], int)
    assert isinstance(fields["e_phoff"], int)
    assert isinstance(fields["e_shoff"], int)
    assert isinstance(fields["e_flags"], int)
    assert isinstance(fields["e_ehsize"], int)
    assert isinstance(fields["e_phentsize"], int)
    assert isinstance(fields["e_phnum"], int)
    assert isinstance(fields["e_shentsize"], int)
    assert isinstance(fields["e_shnum"], int)
    assert isinstance(fields["e_shstrndx"], int)


def test_raising_on_32bit_elf_binary():
    BINARY_PATH = "tests/samples/binaries/binary-32bit"

    with pytest.raises(ValueError, match="ELF binary must be 64-bit"):
        ExecutableHeader(BINARY_PATH).fields()


def test_raising_on_invalid_elf_binary(mocker: MockerFixture):
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"invalid"))

    with pytest.raises(ValueError, match="is not a valid ELF binary"):
        ExecutableHeader("invalid").fields()


def test_raising_on_nonexistent_elf_binary_path():
    with pytest.raises(
        ValueError, match="Could not open ELF binary 'nonexistent'"
    ):
        ExecutableHeader("nonexistent").fields()
