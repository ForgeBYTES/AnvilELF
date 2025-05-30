import re
from typing import Callable

import pytest
from _pytest.fixtures import FixtureRequest

from src.elf.executable_header import RawExecutableHeader
from src.elf.section_header import (
    RawSectionHeader,
    RawSectionHeaders,
    SectionHeader,
    ValidatedSectionHeader,
    ValidatedSectionHeaders,
)


@pytest.fixture
def expected_offset() -> int:
    return 64


@pytest.fixture
def expected_data() -> dict[str, int]:
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
def raw_data(request: FixtureRequest) -> bytearray:
    with open(request.param, "rb") as binary:
        return bytearray(binary.read())


@pytest.mark.parametrize(
    "_class",
    [
        lambda raw_data, offset: RawSectionHeader(
            raw_data=raw_data, offset=offset
        ),
        lambda raw_data, offset: ValidatedSectionHeader(
            RawSectionHeader(
                raw_data=raw_data,
                offset=offset,
            ),
            RawSectionHeaders(raw_data, RawExecutableHeader(raw_data)),
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
        [bytearray, int], RawSectionHeader | ValidatedSectionHeader
    ],
) -> None:
    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    fields = _class(
        raw_data,
        offset + expected_offset,
    ).fields()

    assert fields == expected_data


@pytest.mark.parametrize(
    "_class",
    [
        lambda raw_data, offset: RawSectionHeader(
            raw_data=raw_data, offset=offset
        ),
        lambda raw_data, offset: ValidatedSectionHeader(
            RawSectionHeader(raw_data=raw_data, offset=offset),
            RawSectionHeaders(raw_data, RawExecutableHeader(raw_data)),
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_changing_fields(
    raw_data: bytearray,
    expected_offset: int,
    expected_data: dict[str, int],
    _class: Callable[
        [bytearray, int], RawSectionHeader | ValidatedSectionHeader
    ],
) -> None:
    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    original_sh_flags = 2
    expected_sh_flags = 4

    section_header = _class(
        raw_data,
        offset + expected_offset,
    )

    assert section_header.fields()["sh_flags"] == original_sh_flags

    expected_data["sh_flags"] = expected_sh_flags

    section_header.change(expected_data)

    assert (
        RawSectionHeader(
            raw_data=raw_data, offset=offset + expected_offset
        ).fields()
        == expected_data
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_fields_with_missing_field(
    raw_data: bytearray, expected_offset: int, expected_data: dict[str, int]
) -> None:
    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    expected_data["sh_flags"] = 4

    del expected_data["sh_addr"]

    with pytest.raises(ValueError, match="Unable to process data"):
        RawSectionHeader(
            raw_data=raw_data, offset=offset + expected_offset
        ).change(expected_data)


def test_raising_on_returning_fields_of_unprocessable_binary() -> None:
    with pytest.raises(ValueError, match="Unable to process data"):
        RawSectionHeader(
            raw_data=bytearray(b"unprocessable data"), offset=5
        ).fields()


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_field_with_unprocessable_data_type(
    raw_data: bytearray,
    expected_offset: int,
    expected_data: dict[str, int],
) -> None:
    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    expected_data["sh_flags"] = 2**64

    with pytest.raises(ValueError, match="Unable to process data"):
        RawSectionHeader(
            raw_data=raw_data,
            offset=offset + expected_offset,
        ).change(expected_data)


@pytest.mark.parametrize(
    "_class",
    [
        lambda raw_data: RawSectionHeaders(
            raw_data,
            RawExecutableHeader(raw_data),
        ),
        lambda raw_data: ValidatedSectionHeaders(
            RawSectionHeaders(
                raw_data,
                RawExecutableHeader(raw_data),
            )
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_all_section_headers(
    raw_data: bytearray,
    _class: Callable[[bytearray], RawSectionHeaders | ValidatedSectionHeaders],
) -> None:
    executable_header = RawExecutableHeader(raw_data)
    section_headers = _class(raw_data).all()

    assert len(section_headers) == executable_header.fields()["e_shnum"]
    assert all(
        isinstance(section_header, SectionHeader)
        for section_header in section_headers
    )


@pytest.mark.parametrize(
    "field, value, error_message",
    [
        (
            "sh_type",
            20,
            "Section header (27) contains invalid values:\n  sh_type=20",
        ),
        (
            "sh_flags",
            0xDEADBEEF,
            "Section header (27) contains invalid values:\n"
            f"  sh_flags={0xDEADBEEF}",
        ),
        (
            "sh_addralign",
            3,
            "Section header (27) contains invalid values:\n  sh_addralign=3",
        ),
        (
            "sh_size",
            -1,
            "Section header (27) contains invalid values:\n  sh_size=-1",
        ),
        (
            "sh_offset",
            -1,
            "Section header (27) contains invalid values:\n  sh_offset=-1",
        ),
        (
            "sh_link",
            -1,
            "Section header (27) contains invalid values:\n  sh_link=-1",
        ),
        (
            "invalid",
            2,
            "Section header (27) contains invalid values:\n  invalid=2",
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
    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    expected_data[field] = value

    with pytest.raises(ValueError, match=re.escape(error_message)):
        ValidatedSectionHeader(
            RawSectionHeader(
                raw_data=raw_data, offset=offset + expected_offset
            ),
            RawSectionHeaders(raw_data, RawExecutableHeader(raw_data)),
        ).change(expected_data)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_nonzero_sh_info_in_sht_dynamic(
    raw_data: bytearray,
) -> None:
    expected_data = {
        "sh_name": 253,
        "sh_type": 6,
        "sh_flags": 3,
        "sh_addr": 15816,
        "sh_offset": 11720,
        "sh_size": 496,
        "sh_link": 7,
        "sh_info": 0,
        "sh_addralign": 8,
        "sh_entsize": 16,
    }

    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]
    sht_dynamic_index = 23

    expected_data["sh_info"] = 18

    with pytest.raises(
        ValueError,
        match=re.escape(
            "Section header (253) contains invalid values:\n  sh_info=18"
        ),
    ):
        ValidatedSectionHeader(
            RawSectionHeader(
                raw_data=raw_data, offset=offset + (sht_dynamic_index * 64)
            ),
            RawSectionHeaders(raw_data, RawExecutableHeader(raw_data)),
        ).change(expected_data)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_zero_sh_entsize_in_sht_dynamic(
    raw_data: bytearray,
) -> None:
    expected_data = {
        "sh_name": 253,
        "sh_type": 6,
        "sh_flags": 3,
        "sh_addr": 15816,
        "sh_offset": 11720,
        "sh_size": 496,
        "sh_link": 7,
        "sh_info": 0,
        "sh_addralign": 8,
        "sh_entsize": 16,
    }

    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]
    sht_dynamic_index = 23

    expected_data["sh_entsize"] = 0

    with pytest.raises(
        ValueError,
        match=re.escape(
            "Section header (253) contains invalid values:\n  sh_entsize=0"
        ),
    ):
        ValidatedSectionHeader(
            RawSectionHeader(
                raw_data=raw_data, offset=offset + (sht_dynamic_index * 64)
            ),
            RawSectionHeaders(raw_data, RawExecutableHeader(raw_data)),
        ).change(expected_data)


@pytest.mark.parametrize(
    "sh_flags, sh_addr, sh_addralign, should_pass",
    [
        (0x2, 0x1000, 8, True),
        (0x2, 0x1003, 8, False),
        (0x2, 0x1000, 1, True),
        (0x2, 0x1000, 0, True),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_changing_sh_addr_alignment(
    raw_data: bytearray,
    expected_offset: int,
    expected_data: dict[str, int],
    sh_flags: int,
    sh_addr: int,
    sh_addralign: int,
    should_pass: bool,
) -> None:
    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    section_header = ValidatedSectionHeader(
        RawSectionHeader(raw_data=raw_data, offset=offset + expected_offset),
        RawSectionHeaders(raw_data, RawExecutableHeader(raw_data)),
    )

    expected_data["sh_flags"] = sh_flags
    expected_data["sh_addr"] = sh_addr
    expected_data["sh_addralign"] = sh_addralign

    if should_pass:
        section_header.change(expected_data)
    else:
        with pytest.raises(
            ValueError,
            match=re.escape(
                "Section header (27) contains invalid values:\n  sh_addr=4099"
            ),
        ):
            section_header.change(expected_data)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_multiple_invalid_field_values(
    raw_data: bytearray,
    expected_offset: int,
    expected_data: dict[str, int],
) -> None:
    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    expected_data["sh_type"] = 20
    expected_data["sh_flags"] = 0xDEADBEEF
    expected_data["sh_addralign"] = 3
    expected_data["sh_size"] = -1

    with pytest.raises(
        ValueError,
        match=re.escape(
            "Section header (27) contains invalid values:\n"
            "  sh_type=20\n"
            f"  sh_flags={0xDEADBEEF}\n"
            "  sh_size=-1\n"
            "  sh_addralign=3"
        ),
    ):
        ValidatedSectionHeader(
            RawSectionHeader(
                raw_data=raw_data, offset=offset + expected_offset
            ),
            RawSectionHeaders(raw_data, RawExecutableHeader(raw_data)),
        ).change(expected_data)
