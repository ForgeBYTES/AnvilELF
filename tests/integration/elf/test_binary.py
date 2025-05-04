import shutil
from pathlib import Path
from typing import Callable, Generator
from unittest.mock import patch

import pytest

from src.elf.binary import RawBinary, ValidatedBinary
from src.elf.executable_header import ExecutableHeader
from src.elf.program_header import ProgramHeaders
from src.elf.section import Sections
from src.elf.section_header import SectionHeaders
from src.elf.segment import Segments


@pytest.fixture
def prepare_temporary_binaries() -> Generator[None, None, None]:
    original_path = Path("tests/samples/binaries")
    temporary_path = Path("tests/samples/temporary_binaries")

    for file in original_path.iterdir():
        if file.is_file():  # pragma: no cover
            shutil.copy(file, temporary_path)

    yield

    for file in temporary_path.iterdir():
        if file.name != ".gitkeep":
            file.unlink()


@pytest.mark.parametrize(
    "binary",
    [
        lambda path: RawBinary(path),
        lambda path: ValidatedBinary(RawBinary(path)),
    ],
)
def test_replacing_shstrtab_and_saving_binary(
    prepare_temporary_binaries: Generator[None, None, None],
    binary: Callable[[str], RawBinary | ValidatedBinary],
) -> None:
    path = "tests/samples/temporary_binaries/stripped-binary"
    new_shstrtab = (
        b"\x00.shstrtab\x00.interp\x00.note.gnu.property\x00"
        b".note.gnu.build-id\x00.note.ABI-tag\x00.gnu.hash\x00"
        b".dynsym\x00.dynstr\x00.gnu.version\x00.gnu.version_r\x00"
        b".rela.dyn\x00.rela.plt\x00.init\x00.plt.got\x00.plt.sec\x00"
        b".code\x00.fini\x00.rodata\x00.eh_frame_hdr\x00.eh_frame\x00"
        b".init_array\x00.fini_array\x00.dynamic\x00.data\x00.bss\x00"
        b".comment\x00"
    )
    original_binary = binary(path)

    executable_header, section_header, sections, program_headers, segments = (
        original_binary.components()
    )

    assert isinstance(executable_header, ExecutableHeader)
    assert isinstance(section_header, SectionHeaders)
    assert isinstance(sections, Sections)
    assert isinstance(program_headers, ProgramHeaders)
    assert isinstance(segments, Segments)

    original_data = original_binary.raw_data()[:]

    text_data = sections.find(".text").raw_data().tobytes()

    sections.find(".shstrtab").replace(new_shstrtab)

    original_binary.save()

    assert original_data != original_binary.raw_data()

    duplicate_binary = RawBinary(path)
    _, _, sections, _, _ = duplicate_binary.components()

    assert sections.find(".code").raw_data().tobytes() == text_data


def test_raising_on_saving_binary(
    prepare_temporary_binaries: Generator[None, None, None],
) -> None:
    with patch("builtins.open", side_effect=OSError):
        with pytest.raises(ValueError, match="Failed to save binary"):
            RawBinary("tests/samples/temporary_binaries/binary").save()
