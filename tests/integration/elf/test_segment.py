from typing import Callable

import pytest
from _pytest.fixtures import FixtureRequest

from src.elf.executable_header import RawExecutableHeader
from src.elf.program_header import (
    RawProgramHeader,
    RawProgramHeaders,
    ValidatedProgramHeaders,
)
from src.elf.segment import RawSegment, RawSegments


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
    "segments",
    [
        lambda raw_data: RawSegments(
            raw_data,
            RawProgramHeaders(raw_data, RawExecutableHeader(raw_data)),
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_exceeding_segment_raw_data(
    raw_data: bytearray, segments: Callable[[bytearray], RawSegments]
) -> None:
    exceeding_size = len(raw_data)

    segment = segments(raw_data).all()[0]
    program_header = RawProgramHeader(raw_data, segment.header()["p_offset"])

    fields = segment.header()
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
        if (
            segment.header()["p_type"] == 1
            and segment.header()["p_offset"] == 0
        ):
            segment_data = bytearray(segment.raw_data())
            assert segment_data[:4] == b"\x7fELF"

            segment_data[:4] = b"\x7fFUN"
            segment.replace(bytes(segment_data))

            assert segment.raw_data()[:4] == b"\x7fFUN"


@pytest.mark.parametrize(
    "segments",
    [
        lambda raw_data: RawSegments(
            raw_data,
            RawProgramHeaders(raw_data, RawExecutableHeader(raw_data)),
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_segment_replace_invalid_size(
    raw_data: bytearray, segments: Callable[[bytearray], RawSegments]
) -> None:
    with pytest.raises(ValueError, match="Invalid segment size"):
        segments(raw_data).all()[0].replace(b"invalid size")


@pytest.mark.parametrize(
    "segments",
    [
        lambda raw_data: RawSegments(
            raw_data,
            RawProgramHeaders(raw_data, RawExecutableHeader(raw_data)),
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_segment_raw_data(
    raw_data: bytearray, segments: Callable[[bytearray], RawSegments]
) -> None:
    for segment in segments(raw_data).all():
        assert len(segment.raw_data()) == segment.header()["p_filesz"]
