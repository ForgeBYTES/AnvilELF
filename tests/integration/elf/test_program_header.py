import re
from typing import Callable

import pytest
from _pytest.fixtures import FixtureRequest

from src.elf.executable_header import RawExecutableHeader
from src.elf.program_header import (
    ProgramHeader,
    RawProgramHeader,
    RawProgramHeaders,
    ValidatedProgramHeader,
    ValidatedProgramHeaders,
)


@pytest.fixture
def expected_offset() -> int:
    return 0


@pytest.fixture
def expected_data() -> dict[str, int]:
    return {
        "p_type": 1,
        "p_flags": 5,
        "p_offset": 64,
        "p_vaddr": 0x400000,
        "p_paddr": 0x400000,
        "p_filesz": 1234,
        "p_memsz": 1234,
        "p_align": 8,
    }


@pytest.fixture
def raw_data(request: FixtureRequest) -> bytearray:
    with open(request.param, "rb") as binary:
        return bytearray(binary.read())


@pytest.mark.parametrize(
    "_class",
    [
        lambda raw_data, offset: RawProgramHeader(
            raw_data=raw_data, offset=offset
        ),
        lambda raw_data, offset: ValidatedProgramHeader(
            RawProgramHeader(
                raw_data=raw_data,
                offset=offset,
            ),
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_fields(
    raw_data: bytearray,
    expected_offset: int,
    expected_data: dict[str, int],
    _class: Callable[
        [bytearray, int], RawProgramHeader | ValidatedProgramHeader
    ],
) -> None:
    offset = RawExecutableHeader(raw_data).fields()["e_phoff"]

    fields = _class(
        raw_data,
        offset + expected_offset,
    ).fields()

    for key in expected_data.keys():
        assert key in fields


@pytest.mark.parametrize(
    "_class",
    [
        lambda raw_data, offset: RawProgramHeader(
            raw_data=raw_data, offset=offset
        ),
        lambda raw_data, offset: ValidatedProgramHeader(
            RawProgramHeader(raw_data=raw_data, offset=offset),
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_changing_fields(
    raw_data: bytearray,
    expected_offset: int,
    _class: Callable[
        [bytearray, int], RawProgramHeader | ValidatedProgramHeader
    ],
) -> None:
    offset = RawExecutableHeader(raw_data).fields()["e_phoff"]

    program_header = _class(
        raw_data,
        offset + expected_offset,
    )

    fields = program_header.fields()

    fields["p_flags"] = fields["p_flags"] ^ 0x1

    program_header.change(fields)

    assert (
        RawProgramHeader(
            raw_data=raw_data, offset=offset + expected_offset
        ).fields()["p_flags"]
        == fields["p_flags"]
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_fields_with_missing_field(
    raw_data: bytearray,
    expected_offset: int,
    expected_data: dict[str, int],
) -> None:
    offset = RawExecutableHeader(raw_data).fields()["e_phoff"]

    expected_data["p_flags"] = 5

    del expected_data["p_offset"]

    with pytest.raises(ValueError, match="Unable to process data"):
        RawProgramHeader(
            raw_data=raw_data, offset=offset + expected_offset
        ).change(expected_data)


def test_raising_on_returning_fields_of_unprocessable_binary() -> None:
    with pytest.raises(ValueError, match="Unable to process data"):
        RawProgramHeader(
            raw_data=bytearray(b"unprocessable"), offset=5
        ).fields()


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_field_with_unprocessable_data_type(
    raw_data: bytearray,
    expected_offset: int,
    expected_data: dict[str, int],
) -> None:
    offset = RawExecutableHeader(raw_data).fields()["e_phoff"]

    expected_data["p_flags"] = 2**64

    with pytest.raises(ValueError, match="Unable to process data"):
        RawProgramHeader(
            raw_data=raw_data,
            offset=offset + expected_offset,
        ).change(expected_data)


@pytest.mark.parametrize(
    "_class",
    [
        lambda raw_data: RawProgramHeaders(
            raw_data,
            RawExecutableHeader(raw_data),
        ),
        lambda raw_data: ValidatedProgramHeaders(
            RawProgramHeaders(
                raw_data,
                RawExecutableHeader(raw_data),
            )
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_all_program_headers(
    raw_data: bytearray,
    _class: Callable[[bytearray], RawProgramHeaders | ValidatedProgramHeaders],
) -> None:
    executable_header = RawExecutableHeader(raw_data)
    program_headers = _class(raw_data).all()

    assert len(program_headers) == executable_header.fields()["e_phnum"]
    assert all(
        isinstance(program_header, ProgramHeader)
        for program_header in program_headers
    )


@pytest.mark.parametrize(
    "field, value, error_message",
    [
        (
            "invalid",
            123,
            "Program header (1) contains invalid fields: invalid",
        ),
        (
            "p_type",
            0xFFFFFFFF,
            "Program header (4294967295) contains invalid fields: p_type",
        ),
        (
            "p_align",
            6,
            "Program header (1) contains invalid fields: p_align",
        ),
        (
            "p_flags",
            0xDEADBEEF,
            "Program header (1) contains invalid fields: p_flags",
        ),
        (
            "p_offset",
            -1,
            "Program header (1) contains invalid fields: p_offset",
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_field_with_invalid_value(
    raw_data: bytearray,
    expected_offset: int,
    expected_data: dict[str, int],
    field: str,
    value: int,
    error_message: str,
) -> None:
    offset = RawExecutableHeader(raw_data).fields()["e_phoff"]

    expected_data[field] = value

    with pytest.raises(
        ValueError,
        match=re.escape(error_message),
    ):
        ValidatedProgramHeader(
            RawProgramHeader(
                raw_data=raw_data, offset=offset + expected_offset
            ),
        ).change(expected_data)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_invalid_program_header_metadata(
    raw_data: bytearray,
) -> None:
    executable_header = RawExecutableHeader(raw_data)

    fields = executable_header.fields()

    fields["e_phoff"] = 0
    fields["e_phentsize"] = 0
    fields["e_phnum"] = 0

    executable_header.change(fields)

    with pytest.raises(
        ValueError, match="Program header table metadata is missing or invalid"
    ):
        RawProgramHeaders(raw_data, executable_header).all()


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_multiple_invalid_fields(
    raw_data: bytearray,
    expected_offset: int,
    expected_data: dict[str, int],
) -> None:
    offset = RawExecutableHeader(raw_data).fields()["e_phoff"]

    expected_data["p_flags"] = 0xDEADBEEF
    expected_data["invalid"] = 456

    with pytest.raises(
        ValueError,
        match=re.escape(
            "Program header (1) contains invalid fields: p_flags, invalid"
        ),
    ):
        ValidatedProgramHeader(
            RawProgramHeader(
                raw_data=raw_data,
                offset=offset + expected_offset,
            ),
        ).change(expected_data)
