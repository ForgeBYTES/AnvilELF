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


@pytest.mark.parametrize(
    "_class",
    [
        RawExecutableHeader,
        lambda filename: ValidatedExecutableHeader(
            RawExecutableHeader(filename),
        ),
    ],
)
def test_returning_fields(_class):
    expected_fields = {
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
        "e_entry": 4192,
        "e_phoff": 64,
        "e_shoff": 13984,
        "e_flags": 0,
        "e_ehsize": 64,
        "e_phentsize": 56,
        "e_phnum": 13,
        "e_shentsize": 64,
        "e_shnum": 31,
        "e_shstrndx": 30,
    }
    binary_path = "tests/samples/binaries/binary"

    assert _class(binary_path).fields() == expected_fields


def test_returning_filename():
    expected_path = "tests/samples/binaries/binary"
    assert RawExecutableHeader(expected_path).filename() == expected_path


@pytest.mark.parametrize(
    "_class",
    [
        RawExecutableHeader,
        lambda path: ValidatedExecutableHeader(RawExecutableHeader(path)),
    ],
)
def test_changing_single_field(prepare_temporary_binaries, _class):
    binary_path = "tests/samples/temporary_binaries/binary"

    original_ei_data = 1
    expected_ei_data = 2
    expected_fields = {
        "e_ident": {
            "EI_MAG": b"\x7fELF",
            "EI_CLASS": 2,
            "EI_DATA": expected_ei_data,
            "EI_VERSION": 1,
            "EI_OSABI": 0,
            "EI_ABIVERSION": 0,
            "EI_PAD": b"\x00" * 7,
        },
        "e_type": 3,
        "e_machine": 62,
        "e_version": 1,
        "e_entry": 4192,
        "e_phoff": 64,
        "e_shoff": 13984,
        "e_flags": 0,
        "e_ehsize": 64,
        "e_phentsize": 56,
        "e_phnum": 13,
        "e_shentsize": 64,
        "e_shnum": 31,
        "e_shstrndx": 30,
    }

    executable_header = _class(binary_path)

    assert executable_header.fields()["e_ident"]["EI_DATA"] == original_ei_data

    executable_header.change({"e_ident": {"EI_DATA": expected_ei_data}})

    assert executable_header.fields() == expected_fields


@pytest.mark.parametrize(
    "_class",
    [
        RawExecutableHeader,
        lambda path: ValidatedExecutableHeader(RawExecutableHeader(path)),
    ],
)
def test_changing_multiple_fields(
    prepare_temporary_binaries,
    _class,
):
    binary_path = "tests/samples/temporary_binaries/binary"
    original_ei_data = 1
    original_e_type = 3
    expected_ei_data = 2
    expected_e_type = 1
    expected_fields = {
        "e_ident": {
            "EI_MAG": b"\x7fELF",
            "EI_CLASS": 2,
            "EI_DATA": expected_ei_data,
            "EI_VERSION": 1,
            "EI_OSABI": 0,
            "EI_ABIVERSION": 0,
            "EI_PAD": b"\x00" * 7,
        },
        "e_type": expected_e_type,
        "e_machine": 62,
        "e_version": 1,
        "e_entry": 4192,
        "e_phoff": 64,
        "e_shoff": 13984,
        "e_flags": 0,
        "e_ehsize": 64,
        "e_phentsize": 56,
        "e_phnum": 13,
        "e_shentsize": 64,
        "e_shnum": 31,
        "e_shstrndx": 30,
    }

    executable_header = _class(binary_path)

    assert executable_header.fields()["e_ident"]["EI_DATA"] == original_ei_data
    assert executable_header.fields()["e_type"] == original_e_type

    executable_header.change(
        {
            "e_ident": {"EI_DATA": expected_ei_data},
            "e_type": expected_e_type,
        }
    )

    assert executable_header.fields() == expected_fields


def test_raising_on_returning_fields_using_nonexistent_filename():
    with pytest.raises(ValueError, match="Failed to read file"):
        RawExecutableHeader("nonexistent").fields()


def test_raising_on_returning_nonexistent_filename():
    with pytest.raises(ValueError, match="Filename does not exist"):
        RawExecutableHeader("nonexistent").filename()


def test_raising_on_unprocessable_binary(mocker: MockerFixture):
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"unprocessable"))

    with pytest.raises(ValueError, match="Unable to process binary"):
        RawExecutableHeader("invalid").fields()


def test_raising_on_32bit_type():
    binary_path = "tests/samples/binaries/binary-32bit"

    with pytest.raises(ValueError, match="Binary must be 64-bit"):
        ValidatedExecutableHeader(RawExecutableHeader(binary_path)).fields()


def test_raising_on_getting_fields_with_malformed_ei_data():
    binary_path = "tests/samples/binaries/binary-with-malformed-ei-data"

    with pytest.raises(ValueError, match="Invalid value for EI_DATA"):
        ValidatedExecutableHeader(RawExecutableHeader(binary_path)).fields()


def test_raising_on_getting_fields_with_malformed_ei_version():
    binary_path = "tests/samples/binaries/binary-with-malformed-ei-version"

    with pytest.raises(ValueError, match="Invalid value for EI_VERSION"):
        ValidatedExecutableHeader(RawExecutableHeader(binary_path)).fields()


def test_raising_on_getting_fields_with_malformed_e_type():
    binary_path = "tests/samples/binaries/binary-with-malformed-e-type"

    with pytest.raises(ValueError, match="Invalid value for e_type"):
        ValidatedExecutableHeader(RawExecutableHeader(binary_path)).fields()


def test_raising_on_changing_invalid_field(
    prepare_temporary_binaries,
):
    binary_path = "tests/samples/temporary_binaries/binary"

    with pytest.raises(ValueError, match="Unknown field invalid"):
        ValidatedExecutableHeader(RawExecutableHeader(binary_path)).change(
            {"invalid": 1}
        )


def test_raising_on_changing_invalid_e_ident_field(
    prepare_temporary_binaries,
):
    binary_path = "tests/samples/temporary_binaries/binary"

    with pytest.raises(ValueError, match="Unknown field invalid"):
        ValidatedExecutableHeader(RawExecutableHeader(binary_path)).change(
            {"e_ident": {"invalid": 1}}
        )


@pytest.mark.parametrize(
    "field, invalid_value, error_message",
    [
        (
            "e_ident",
            {"EI_MAG": b"invalid"},
            "Invalid value for EI_MAG",
        ),
        ("e_ident", {"EI_DATA": 3}, "Invalid value for EI_DATA"),
        ("e_ident", {"EI_VERSION": 2}, "Invalid value for EI_VERSION"),
        ("e_type", 5, "Invalid value for e_type"),
        ("e_shoff", 7, "Invalid value for e_shoff"),
        ("e_entry", 0, "Invalid value for e_entry"),
        ("e_ehsize", 32, "Invalid value for e_ehsize"),
        ("e_phentsize", 128, "Invalid value for e_phentsize"),
        ("e_shentsize", 128, "Invalid value for e_shentsize"),
        ("e_flags", 0xDEADBEEF, "Nonzero e_flags unexpected for x86-64"),
    ],
)
def test_raising_on_changing_invalid_field_values(
    prepare_temporary_binaries, field, invalid_value, error_message
):
    binary_path = "tests/samples/temporary_binaries/binary"

    with pytest.raises(ValueError, match=error_message):
        ValidatedExecutableHeader(RawExecutableHeader(binary_path)).change(
            {field: invalid_value}
        )


def test_no_change_does_nothing(prepare_temporary_binaries):
    binary_path = "tests/samples/temporary_binaries/binary"

    executable_header = RawExecutableHeader(binary_path)
    original_fields = executable_header.fields()

    executable_header.change({})

    assert executable_header.fields() == original_fields
