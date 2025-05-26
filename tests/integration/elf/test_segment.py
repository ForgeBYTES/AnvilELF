from typing import Callable

import pytest
from _pytest.fixtures import FixtureRequest

from src.elf.executable_header import RawExecutableHeader
from src.elf.program_header import (
    ProgramHeader,
    RawProgramHeader,
    RawProgramHeaders,
    ValidatedProgramHeaders,
)
from src.elf.segment import (
    DynamicEntry,
    RawDynamic,
    RawDynamicEntry,
    RawSegment,
    RawSegments,
    ValidatedDynamic,
)


@pytest.fixture
def raw_data(request: FixtureRequest) -> bytearray:
    with open(request.param, "rb") as binary:
        return bytearray(binary.read())


@pytest.mark.parametrize(
    "segments",
    [
        lambda raw_data: RawSegments(
            raw_data,
            RawProgramHeaders(raw_data, RawExecutableHeader(raw_data)),
        ),
        lambda raw_data: RawSegments(
            raw_data,
            ValidatedProgramHeaders(
                RawProgramHeaders(raw_data, RawExecutableHeader(raw_data))
            ),
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_returning_segments_types(
    raw_data: bytearray, segments: Callable[[bytearray], RawSegments]
) -> None:
    # fmt: off
    expected_types: list[str] = [
        "6", "3", "1", "1", "1", "1", "2", "4", "4",
        "1685382483", "1685382480", "1685382481", "1685382482",
    ]
    # fmt: on
    assert [
        segment.type() for segment in segments(raw_data).all()
    ] == expected_types


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_exceeding_segment_raw_data(raw_data: bytearray) -> None:
    exceeding_size = len(raw_data)

    segment = RawSegments(
        raw_data,
        RawProgramHeaders(raw_data, RawExecutableHeader(raw_data)),
    ).all()[0]
    program_header = RawProgramHeader(
        raw_data, segment.header().fields()["p_offset"]
    )

    fields = segment.header().fields()
    fields["p_offset"] = exceeding_size
    program_header.change(fields)

    broken_segment = RawSegment(raw_data, program_header)

    with pytest.raises(ValueError, match="Exceeded segment size"):
        broken_segment.raw_data()


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_replacing_elf_magic_with_fun(raw_data: bytearray) -> None:
    segments = RawSegments(
        raw_data,
        RawProgramHeaders(raw_data, RawExecutableHeader(raw_data)),
    ).all()

    for segment in segments:
        header = segment.header().fields()
        if header["p_type"] == 1 and header["p_offset"] == 0:
            segment_data = bytearray(segment.raw_data())
            assert segment_data[:4] == b"\x7fELF"

            segment_data[:4] = b"\x7fFUN"
            segment.replace(bytes(segment_data))

            assert segment.raw_data()[:4] == b"\x7fFUN"


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_segment_replace_invalid_size(raw_data: bytearray) -> None:
    with pytest.raises(ValueError, match="Invalid segment size"):
        RawSegments(
            raw_data,
            RawProgramHeaders(raw_data, RawExecutableHeader(raw_data)),
        ).all()[0].replace(b"invalid size")


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_segment_raw_data(raw_data: bytearray) -> None:
    segments = RawSegments(
        raw_data,
        RawProgramHeaders(raw_data, RawExecutableHeader(raw_data)),
    )
    for segment in segments.all():
        assert len(segment.raw_data()) == segment.header().fields()["p_filesz"]


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_all_dynamic_entries(raw_data: bytearray) -> None:
    expected_entries = [
        {"d_tag": 1, "d_un": 41},
        {"d_tag": 12, "d_un": 4096},
        {"d_tag": 13, "d_un": 4472},
        {"d_tag": 25, "d_un": 15800},
        {"d_tag": 27, "d_un": 8},
        {"d_tag": 26, "d_un": 15808},
        {"d_tag": 28, "d_un": 8},
        {"d_tag": 1879047925, "d_un": 944},
        {"d_tag": 5, "d_un": 1152},
        {"d_tag": 6, "d_un": 984},
        {"d_tag": 10, "d_un": 143},
        {"d_tag": 11, "d_un": 24},
        {"d_tag": 21, "d_un": 0},
        {"d_tag": 3, "d_un": 16312},
        {"d_tag": 2, "d_un": 24},
        {"d_tag": 20, "d_un": 7},
        {"d_tag": 23, "d_un": 1552},
        {"d_tag": 7, "d_un": 1360},
        {"d_tag": 8, "d_un": 192},
        {"d_tag": 9, "d_un": 24},
        {"d_tag": 30, "d_un": 8},
        {"d_tag": 1879048187, "d_un": 134217729},
        {"d_tag": 1879048190, "d_un": 1312},
        {"d_tag": 1879048191, "d_un": 1},
        {"d_tag": 1879048176, "d_un": 1296},
        {"d_tag": 1879048185, "d_un": 3},
        {"d_tag": 0, "d_un": 0},
        {"d_tag": 0, "d_un": 0},
        {"d_tag": 0, "d_un": 0},
        {"d_tag": 0, "d_un": 0},
        {"d_tag": 0, "d_un": 0},
    ]

    segments = RawSegments(
        raw_data, RawProgramHeaders(raw_data, RawExecutableHeader(raw_data))
    )
    assert [
        entry.fields()
        for entry in ValidatedDynamic(
            RawDynamic(segments.occurrence(ProgramHeader.PT_DYNAMIC))
        ).all()
    ] == expected_entries


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_changing_dynamic_entry(raw_data: bytearray) -> None:
    segments = RawSegments(
        raw_data, RawProgramHeaders(raw_data, RawExecutableHeader(raw_data))
    )
    for entry in ValidatedDynamic(
        RawDynamic(segments.occurrence(ProgramHeader.PT_DYNAMIC))
    ).all():
        fields = entry.fields()
        if fields["d_tag"] == DynamicEntry.DT_NEEDED:

            new_d_un = fields["d_un"] + 32
            fields["d_un"] = new_d_un
            entry.change(fields)

            assert entry.fields()["d_un"] == new_d_un


def test_raising_on_returning_unprocessable_dynamic_entry_fields() -> None:
    with pytest.raises(ValueError, match="Unable to process data"):
        RawDynamicEntry(memoryview(b"unprocessable data"), 123).fields()


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_dynamic_entry_fields_with_missing_field(
    raw_data: bytearray,
) -> None:
    segments = RawSegments(
        raw_data, RawProgramHeaders(raw_data, RawExecutableHeader(raw_data))
    )
    for entry in ValidatedDynamic(
        RawDynamic(segments.occurrence(ProgramHeader.PT_DYNAMIC))
    ).all():
        fields = entry.fields()
        if fields["d_tag"] == DynamicEntry.DT_NEEDED:

            with pytest.raises(ValueError, match="Unable to process data"):
                del fields["d_un"]
                entry.change(fields)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_dynamic_entry_with_invalid_fields(
    raw_data: bytearray,
) -> None:
    expected_error = (
        "Dynamic entry contains invalid values:\n"
        "  d_tag=123\n"
        "  invalid=123"
    )

    segments = RawSegments(
        raw_data, RawProgramHeaders(raw_data, RawExecutableHeader(raw_data))
    )
    for entry in ValidatedDynamic(
        RawDynamic(segments.occurrence(ProgramHeader.PT_DYNAMIC))
    ).all():
        fields = entry.fields()
        if fields["d_tag"] == DynamicEntry.DT_NEEDED:

            with pytest.raises(ValueError, match=expected_error):
                fields["d_tag"] = 123
                fields["invalid"] = 123
                entry.change(fields)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_nonexistent_segment(raw_data: bytearray) -> None:
    expected_error = (
        f"No segment found with p_type {0xDEADBEEF}"
        f" and p_flags 0x{0xDEADBEEF:X}"
    )
    with pytest.raises(ValueError, match=expected_error):
        RawSegments(
            raw_data,
            RawProgramHeaders(raw_data, RawExecutableHeader(raw_data)),
        ).occurrence(0xDEADBEEF, 0xDEADBEEF)
