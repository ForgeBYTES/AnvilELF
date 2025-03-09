import pytest
from pytest_mock import MockerFixture

from src.elf.executable_header import (
    RawExecutableHeader,
    ValidatedExecutableHeader,
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


def test_returning_valid_executable_header():
    binary_path = "tests/samples/binaries/binary"
    expected_output = {
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

    fields = RawExecutableHeader(binary_path).fields()

    assert fields["e_ident"] == expected_output["e_ident"]
    assert fields["e_type"] == expected_output["e_type"]
    assert fields["e_machine"] == expected_output["e_machine"]
    assert fields["e_version"] == expected_output["e_version"]


def test_changing_single_field_in_executable_header(
    prepare_temporary_binaries,
):
    binary_path = "tests/samples/temporary_binaries/binary"

    original_ei_data = 1
    expected_ei_data = 2

    executable_header = RawExecutableHeader(binary_path)

    assert executable_header.fields()["e_ident"]["EI_DATA"] == original_ei_data

    executable_header.change({"e_ident": {"EI_DATA": expected_ei_data}})

    assert executable_header.fields()["e_ident"]["EI_DATA"] == expected_ei_data


def test_changing_multiple_fields_in_executable_header(
    prepare_temporary_binaries,
):
    binary_path = "tests/samples/temporary_binaries/binary"

    original_ei_data = 1
    original_e_type = 3

    expected_ei_data = 2
    expected_e_type = 1

    executable_header = RawExecutableHeader(binary_path)

    assert executable_header.fields()["e_ident"]["EI_DATA"] == original_ei_data
    assert executable_header.fields()["e_type"] == original_e_type

    executable_header.change(
        {
            "e_ident": {"EI_DATA": expected_ei_data},
            "e_type": expected_e_type,
        }
    )

    assert executable_header.fields()["e_ident"]["EI_DATA"] == expected_ei_data
    assert executable_header.fields()["e_type"] == expected_e_type


def test_raising_on_nonexistent_elf_binary_path():
    with pytest.raises(ValueError, match="Failed to read ELF binary"):
        RawExecutableHeader("nonexistent").fields()


def test_raising_on_unprocessable_file(mocker: MockerFixture):
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"unprocessable"))

    with pytest.raises(ValueError, match="Unable to process ELF binary"):
        RawExecutableHeader("invalid").fields()


def test_raising_on_elf_binary_with_malformed_ei_data():
    binary_path = "tests/samples/binaries/binary-with-malformed-ei-data"

    with pytest.raises(ValueError, match="ELF binary structure is not valid"):
        ValidatedExecutableHeader(RawExecutableHeader(binary_path)).fields()


def test_raising_on_elf_binary_with_malformed_ei_version():
    binary_path = "tests/samples/binaries/binary-with-malformed-ei-version"

    with pytest.raises(ValueError, match="ELF binary structure is not valid"):
        ValidatedExecutableHeader(RawExecutableHeader(binary_path)).fields()


def test_raising_on_elf_binary_with_malformed_e_type():
    binary_path = "tests/samples/binaries/binary-with-malformed-e-type"

    with pytest.raises(ValueError, match="ELF binary structure is not valid"):
        ValidatedExecutableHeader(RawExecutableHeader(binary_path)).fields()


def test_raising_on_32bit_elf_binary():
    binary_path = "tests/samples/binaries/binary-32bit"

    with pytest.raises(ValueError, match="ELF binary must be 64-bit"):
        ValidatedExecutableHeader(RawExecutableHeader(binary_path)).fields()


def test_raising_on_changing_invalid_field_in_executable_header(
    prepare_temporary_binaries,
):
    binary_path = "tests/samples/temporary_binaries/binary"

    with pytest.raises(ValueError, match="ELF binary structure is not valid"):
        ValidatedExecutableHeader(RawExecutableHeader(binary_path)).change(
            {"invalid": 1}
        )


def test_raising_on_changing_invalid_e_ident_field_in_executable_header(
    prepare_temporary_binaries,
):
    binary_path = "tests/samples/temporary_binaries/binary"

    with pytest.raises(ValueError, match="ELF binary structure is not valid"):
        ValidatedExecutableHeader(RawExecutableHeader(binary_path)).change(
            {"e_ident": {"invalid": 1}}
        )


@pytest.mark.parametrize(
    "field, invalid_value",
    [
        ("e_ident", {"EI_MAG": b"invalid"}),
        ("e_ident", {"EI_DATA": 3}),
        ("e_ident", {"EI_VERSION": 2}),
        ("e_type", 5),
    ],
)
def test_raising_on_changing_disallowed_field_values(
    prepare_temporary_binaries, field, invalid_value
):
    binary_path = "tests/samples/temporary_binaries/binary"

    with pytest.raises(ValueError, match="ELF binary structure is not valid"):
        ValidatedExecutableHeader(RawExecutableHeader(binary_path)).change(
            {field: invalid_value}
        )
