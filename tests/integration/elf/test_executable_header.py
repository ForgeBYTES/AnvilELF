from typing import Any, Callable

import pytest
from _pytest.fixtures import FixtureRequest

from src.elf.executable_header import (
    RawExecutableHeader,
    ValidatedExecutableHeader,
)


@pytest.fixture
def expected_data() -> dict[str, Any]:
    return {
        "e_ident": {
            "ei_mag": b"\x7fELF",
            "ei_class": 2,
            "ei_data": 1,
            "ei_version": 1,
            "ei_osabi": 0,
            "ei_abiversion": 0,
            "ei_pad": b"\x00" * 7,
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
def raw_data(request: FixtureRequest) -> bytearray:
    with open(request.param, "rb") as binary:
        return bytearray(binary.read())


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
def test_returning_fields(
    raw_data: bytearray,
    _class: Callable[
        [bytearray], RawExecutableHeader | ValidatedExecutableHeader
    ],
    expected_data: dict[str, Any],
) -> None:
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
    raw_data: bytearray,
    _class: Callable[
        [bytearray], RawExecutableHeader | ValidatedExecutableHeader
    ],
    expected_data: dict[str, Any],
) -> None:
    original_ei_data = 1
    original_e_type = 3
    expected_ei_data = 2
    expected_e_type = 1

    expected_data["e_ident"]["ei_data"] = expected_ei_data
    expected_data["e_type"] = expected_e_type

    executable_header = _class(raw_data)

    original_fields = executable_header.fields()

    assert original_fields["e_ident"]["ei_data"] == original_ei_data
    assert original_fields["e_type"] == original_e_type

    executable_header.change(expected_data)

    assert RawExecutableHeader(raw_data).fields() == expected_data


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_fields_with_missing_field_in_expected_data(
    raw_data: bytearray, expected_data: dict[str, Any]
) -> None:
    expected_data["sh_flags"] = 4

    del expected_data["e_type"]

    with pytest.raises(ValueError, match="Unable to process data"):
        RawExecutableHeader(raw_data).change(expected_data)


def test_raising_on_returning_fields_of_unprocessable_binary() -> None:
    with pytest.raises(ValueError, match="Unable to process data"):
        RawExecutableHeader(bytearray(b"unprocessable data")).fields()


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_field_with_unprocessable_data_type(
    raw_data: bytearray,
    expected_data: dict[str, Any],
) -> None:
    expected_data["e_type"] = "unprocessable data type"

    with pytest.raises(ValueError, match="Unable to process data"):
        RawExecutableHeader(raw_data).change(expected_data)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_invalid_field(
    raw_data: bytearray,
    expected_data: dict[str, Any],
) -> None:
    expected_data["invalid"] = 1

    with pytest.raises(
        ValueError,
        match="Executable header contains invalid values:\n  invalid=1",
    ):
        ValidatedExecutableHeader(RawExecutableHeader(raw_data)).change(
            expected_data
        )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_invalid_e_ident_field(
    raw_data: bytearray, expected_data: dict[str, Any]
) -> None:
    expected_data["e_ident"]["invalid"] = 1

    with pytest.raises(
        ValueError,
        match="Executable header contains invalid values:\n  invalid=1",
    ):
        ValidatedExecutableHeader(RawExecutableHeader(raw_data)).change(
            expected_data
        )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
@pytest.mark.parametrize(
    "field, invalid_value, error_message",
    [
        (
            "e_type",
            5,
            "Executable header contains invalid values:\n  e_type=5",
        ),
        (
            "e_shoff",
            7,
            "Executable header contains invalid values:\n  e_shoff=7",
        ),
        (
            "e_entry",
            0,
            "Executable header contains invalid values:\n  e_entry=0",
        ),
        (
            "e_ehsize",
            32,
            "Executable header contains invalid values:\n  e_ehsize=32",
        ),
        (
            "e_phentsize",
            64,
            "Executable header contains invalid values:\n  e_phentsize=64",
        ),
        (
            "e_shentsize",
            128,
            "Executable header contains invalid values:\n  e_shentsize=128",
        ),
        (
            "e_flags",
            0xDEADBEEF,
            f"Executable header contains invalid values:\n"
            f"  e_flags={0xDEADBEEF}",
        ),
    ],
)
def test_raising_on_changing_field_with_invalid_value(
    raw_data: bytearray,
    expected_data: dict[str, Any],
    field: str,
    invalid_value: int,
    error_message: str,
) -> None:
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
        (
            "ei_mag",
            b"invalid",
            "Executable header contains invalid values:\n  ei_mag=b'invalid'",
        ),
        (
            "ei_data",
            3,
            "Executable header contains invalid values:\n  ei_data=3",
        ),
        (
            "ei_version",
            2,
            "Executable header contains invalid values:\n  ei_version=2",
        ),
    ],
)
def test_raising_on_changing_e_ident_field_with_invalid_value(
    raw_data: bytearray,
    expected_data: dict[str, Any],
    field: str,
    invalid_value: bytes | int,
    error_message: str,
) -> None:
    expected_data["e_ident"][field] = invalid_value

    with pytest.raises(ValueError, match=error_message):
        ValidatedExecutableHeader(RawExecutableHeader(raw_data)).change(
            expected_data
        )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_multiple_fields_with_invalid_values(
    raw_data: bytearray,
    expected_data: dict[str, Any],
) -> None:
    expected_data["e_ident"]["ei_mag"] = b"invalid"
    expected_data["e_ident"]["ei_version"] = 2
    expected_data["e_flags"] = 0xDEADBEEF
    expected_data["e_shentsize"] = 128

    with pytest.raises(
        ValueError,
        match=(
            "Executable header contains invalid values:\n"
            "  ei_mag=b'invalid'\n"
            "  ei_version=2\n"
            f"  e_flags={0xDEADBEEF}\n"
            "  e_shentsize=128"
        ),
    ):
        ValidatedExecutableHeader(RawExecutableHeader(raw_data)).change(
            expected_data
        )
