import pytest

from src.elf.executable_header import RawExecutableHeader
from src.elf.section_header import (
    RawSectionHeader,
    RawSectionHeaders,
    SectionHeader,
    ValidatedSectionHeader,
    ValidatedSectionHeaders,
)


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
def raw_data(request) -> bytearray:
    with open(request.param, "rb") as f:
        return bytearray(f.read())


@pytest.mark.parametrize(
    "_class",
    [
        RawSectionHeader,
        lambda raw_data, offset: ValidatedSectionHeader(
            RawSectionHeader(
                raw_data=raw_data,
                offset=offset,
            )
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_fields(raw_data, expected_data, _class):
    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    fields = _class(
        raw_data=raw_data,
        offset=offset + 64,
    ).fields()

    assert fields == expected_data


@pytest.mark.parametrize(
    "_class",
    [
        RawSectionHeader,
        lambda raw_data, offset: ValidatedSectionHeader(
            RawSectionHeader(
                raw_data=raw_data,
                offset=offset,
            )
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_changing_fields(raw_data, expected_data, _class):
    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    original_sh_flags = 2
    expected_sh_flags = 4

    section_header = _class(
        raw_data=raw_data,
        offset=offset + 64,
    )

    assert section_header.fields()["sh_flags"] == original_sh_flags

    expected_data["sh_flags"] = expected_sh_flags

    section_header.change(expected_data)

    assert section_header.fields() == expected_data


@pytest.mark.parametrize(
    "_class",
    [
        RawSectionHeader,
        lambda raw_data, offset: ValidatedSectionHeader(
            RawSectionHeader(
                raw_data=raw_data,
                offset=offset,
            )
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_string_representation(raw_data, expected_data, _class):
    expected_string = (
        "Section Header:\n"
        "  Type: 1\n"
        "  Flags: 0x2\n"
        "  Addr: 0x318\n"
        "  Offset: 792\n"
        "  Size: 28 bytes\n"
        "  Align: 1\n"
    )

    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    assert (
        str(_class(raw_data=raw_data, offset=offset + 64)) == expected_string
    )


@pytest.mark.parametrize(
    "_class",
    [
        RawSectionHeader,
        lambda raw_data, offset: ValidatedSectionHeader(
            RawSectionHeader(
                raw_data=raw_data,
                offset=offset,
            )
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
        "Section Header:\n"
        "  Type: 1\n"
        "  Flags: 0x2\n"
        "  Addr: 0x318\n"
        "  Offset: 792\n"
        "  Size: 28 bytes\n"
        "  Align: 1\n"
    )

    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    assert (
        str(_class(raw_data=raw_data, offset=offset + 64)) == expected_string
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_fields_with_missing_key_in_expected_data(
    raw_data, expected_data
):
    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    expected_data["sh_flags"] = 4

    del expected_data["sh_addr"]

    with pytest.raises(ValueError, match="Unable to process data"):
        RawSectionHeader(raw_data=raw_data, offset=offset + 64).change(
            expected_data
        )


def test_raising_on_returning_fields_of_unprocessable_binary():
    with pytest.raises(ValueError, match="Unable to process data"):
        RawSectionHeader(
            raw_data=bytearray(b"unprocessable data"), offset=5
        ).fields()


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_field_with_unprocessable_data_type(
    raw_data, expected_data
):
    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    expected_data["sh_flags"] = "unprocessable data type"

    with pytest.raises(ValueError, match="Unable to process data"):
        RawSectionHeader(
            raw_data=raw_data,
            offset=offset + 64,
        ).change(expected_data)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_all_section_headers(raw_data):
    executable_header = RawExecutableHeader(raw_data)
    section_headers = RawSectionHeaders(raw_data, executable_header).all()

    assert len(section_headers) == executable_header.fields()["e_shnum"]
    assert all(
        isinstance(section_header, SectionHeader)
        for section_header in section_headers
    )


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
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_invalid_field_values(
    raw_data, expected_data, field, value, error_message
):
    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    expected_data[field] = value

    with pytest.raises(ValueError, match=error_message):
        ValidatedSectionHeader(
            RawSectionHeader(raw_data=raw_data, offset=offset + 64)
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
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_changing_sh_addr_alignment(
    raw_data,
    expected_data,
    sh_flags,
    sh_addr,
    sh_addralign,
    should_pass,
):
    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    section_header = ValidatedSectionHeader(
        RawSectionHeader(raw_data=raw_data, offset=offset + 64)
    )

    expected_data["sh_flags"] = sh_flags
    expected_data["sh_addr"] = sh_addr
    expected_data["sh_addralign"] = sh_addralign

    if should_pass:
        section_header.change(expected_data)
    else:
        with pytest.raises(ValueError, match="Invalid value for sh_addr"):
            section_header.change(expected_data)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_all_validated_section_headers_and_their_fields(raw_data):
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

    executable_header = RawExecutableHeader(raw_data)
    section_headers = ValidatedSectionHeaders(
        RawSectionHeaders(raw_data, executable_header)
    ).all()

    assert len(section_headers) == executable_header.fields()["e_shnum"]
    assert all(
        isinstance(section_header, ValidatedSectionHeader)
        for section_header in section_headers
    )

    for section_header in section_headers:
        assert list(section_header.fields().keys()) == expected_fields
