import pytest

from src.elf.executable_header import (
    RawExecutableHeader,
    ValidatedExecutableHeader,
)


@pytest.fixture
def expected_data():
    return {
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


@pytest.fixture
def raw_data(request) -> bytearray:
    with open(request.param, "rb") as f:
        return bytearray(f.read())


@pytest.mark.parametrize(
    "_class",
    [
        RawExecutableHeader,
        lambda raw_data: ValidatedExecutableHeader(
            RawExecutableHeader(raw_data),
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_fields(raw_data, expected_data, _class):
    assert _class(raw_data).fields() == expected_data


@pytest.mark.parametrize(
    "_class",
    [
        RawExecutableHeader,
        lambda raw_data: ValidatedExecutableHeader(
            RawExecutableHeader(raw_data)
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_changing_fields(
    raw_data,
    _class,
    expected_data,
):
    original_ei_data = 1
    original_e_type = 3
    expected_ei_data = 2
    expected_e_type = 1

    expected_data["e_ident"]["EI_DATA"] = expected_ei_data
    expected_data["e_type"] = expected_e_type

    executable_header = _class(raw_data)

    original_fields = executable_header.fields()

    assert original_fields["e_ident"]["EI_DATA"] == original_ei_data
    assert original_fields["e_type"] == original_e_type

    executable_header.change(expected_data)

    assert executable_header.fields() == expected_data


@pytest.mark.parametrize(
    "_class",
    [
        RawExecutableHeader,
        lambda raw_data: ValidatedExecutableHeader(
            RawExecutableHeader(raw_data),
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_string_representation(raw_data, expected_data, _class):
    expected_string = (
        "Executable Header:\n"
        "  Magic: 7f 45 4c 46\n"
        "  Class: 2\n"
        "  Data: 1\n"
        "  Version: 1\n"
        "  OS/ABI: 0\n"
        "  ABI Version: 0\n"
        "  Type: 3\n"
        "  Machine: 62\n"
        "  Entry point: 0x1260\n"
        "  Start of section headers: 19232\n"
        "  Number of section headers: 39\n"
    )
    assert str(_class(raw_data)) == expected_string


@pytest.mark.parametrize(
    "_class",
    [
        RawExecutableHeader,
        lambda raw_data: ValidatedExecutableHeader(
            RawExecutableHeader(raw_data),
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_string_representation_on_stripped_binary(
    raw_data, expected_data, _class
):
    expected_string = (
        "Executable Header:\n"
        "  Magic: 7f 45 4c 46\n"
        "  Class: 2\n"
        "  Data: 1\n"
        "  Version: 1\n"
        "  OS/ABI: 0\n"
        "  ABI Version: 0\n"
        "  Type: 3\n"
        "  Machine: 62\n"
        "  Entry point: 0x1260\n"
        "  Start of section headers: 12616\n"
        "  Number of section headers: 29\n"
    )
    assert str(_class(raw_data)) == expected_string


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_fields_with_missing_key_in_expected_data(
    raw_data, expected_data
):
    expected_data["sh_flags"] = 4

    del expected_data["e_type"]

    with pytest.raises(ValueError, match="Unable to process data"):
        RawExecutableHeader(raw_data).change(expected_data)


def test_raising_on_returning_fields_of_unprocessable_binary():
    with pytest.raises(ValueError, match="Unable to process data"):
        RawExecutableHeader(bytearray(b"unprocessable data")).fields()


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_field_with_unprocessable_data_type(
    raw_data,
    expected_data,
):
    expected_data["e_type"] = "unprocessable data type"

    with pytest.raises(ValueError, match="Unable to process data"):
        RawExecutableHeader(raw_data).change(expected_data)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-32bit"], indirect=True
)
def test_raising_on_32bit_type(raw_data):
    with pytest.raises(ValueError, match="Binary must be 64-bit"):
        ValidatedExecutableHeader(RawExecutableHeader(raw_data)).fields()


@pytest.mark.parametrize(
    "raw_data",
    ["tests/samples/binaries/binary-with-malformed-ei-data"],
    indirect=True,
)
def test_raising_on_getting_fields_with_malformed_ei_data(raw_data):
    with pytest.raises(ValueError, match="Invalid value for EI_DATA"):
        ValidatedExecutableHeader(RawExecutableHeader(raw_data)).fields()


@pytest.mark.parametrize(
    "raw_data",
    ["tests/samples/binaries/binary-with-malformed-ei-version"],
    indirect=True,
)
def test_raising_on_getting_fields_with_malformed_ei_version(raw_data):
    with pytest.raises(ValueError, match="Invalid value for EI_VERSION"):
        ValidatedExecutableHeader(RawExecutableHeader(raw_data)).fields()


@pytest.mark.parametrize(
    "raw_data",
    ["tests/samples/binaries/binary-with-malformed-e-type"],
    indirect=True,
)
def test_raising_on_getting_fields_with_malformed_e_type(raw_data):
    with pytest.raises(ValueError, match="Invalid value for e_type"):
        ValidatedExecutableHeader(RawExecutableHeader(raw_data)).fields()


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_invalid_field(
    raw_data,
    expected_data,
):
    expected_data["invalid"] = 1

    with pytest.raises(ValueError, match="Unknown field invalid"):
        ValidatedExecutableHeader(RawExecutableHeader(raw_data)).change(
            expected_data
        )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_invalid_e_ident_field(raw_data, expected_data):
    expected_data["e_ident"]["invalid"] = 1

    with pytest.raises(ValueError, match="Unknown field invalid"):
        ValidatedExecutableHeader(RawExecutableHeader(raw_data)).change(
            expected_data
        )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
@pytest.mark.parametrize(
    "field, invalid_value, error_message",
    [
        ("e_type", 5, "Invalid value for e_type"),
        ("e_shoff", 7, "Invalid value for e_shoff"),
        ("e_entry", 0, "Invalid value for e_entry"),
        ("e_ehsize", 32, "Invalid value for e_ehsize"),
        ("e_phentsize", 64, "Invalid value for e_phentsize"),
        ("e_shentsize", 128, "Invalid value for e_shentsize"),
        ("e_flags", 0xDEADBEEF, "Nonzero e_flags unexpected for x86-64"),
    ],
)
def test_raising_on_changing_invalid_field_values(
    raw_data,
    expected_data,
    field,
    invalid_value,
    error_message,
):
    expected_data[field] = invalid_value

    with pytest.raises(ValueError, match=error_message):
        ValidatedExecutableHeader(RawExecutableHeader(raw_data)).change(
            expected_data
        )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
@pytest.mark.parametrize(
    "field, invalid_value, error_message",
    [
        ("EI_MAG", b"invalid", "Invalid value for EI_MAG"),
        ("EI_DATA", 3, "Invalid value for EI_DATA"),
        ("EI_VERSION", 2, "Invalid value for EI_VERSION"),
    ],
)
def test_raising_on_changing_invalid_e_ident_field_values(
    raw_data,
    expected_data,
    field,
    invalid_value,
    error_message,
):
    expected_data["e_ident"][field] = invalid_value

    with pytest.raises(ValueError, match=error_message):
        ValidatedExecutableHeader(RawExecutableHeader(raw_data)).change(
            expected_data
        )
