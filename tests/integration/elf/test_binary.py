import shutil
from pathlib import Path

import pytest

from src.elf.binary import RawBinary, ValidatedBinary
from src.elf.executable_header import ExecutableHeader
from src.elf.section import RawStringTable, RawSymbolTable, Sections, Symbol
from src.elf.section_header import SectionHeaders


@pytest.fixture
def prepare_temporary_binaries():
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
def test_changing_symbol_type_and_saving_binary(
    prepare_temporary_binaries, binary
):
    path = "tests/samples/temporary_binaries/binary"
    symbol_type = (Symbol.STB_GLOBAL << 4) | Symbol.STT_FUNC
    original_binary = binary(path)

    executable_header, section_header, sections = original_binary.components()

    assert isinstance(executable_header, ExecutableHeader)
    assert isinstance(section_header, SectionHeaders)
    assert isinstance(sections, Sections)

    original_data = original_binary.raw_data()[:]

    symbol = RawSymbolTable(
        sections.find(".symtab"), RawStringTable(sections.find(".strtab"))
    ).symbols()[1]
    symbol_fields = symbol.fields()

    assert symbol_fields["st_info"] != symbol_type

    symbol_fields["st_info"] = symbol_type
    symbol.change(symbol_fields)

    original_binary.save()

    assert original_data != original_binary.raw_data()

    duplicate_binary = RawBinary(path)

    assert original_binary.raw_data() == duplicate_binary.raw_data()

    _, _, sections = duplicate_binary.components()

    duplicate_symbol = RawSymbolTable(
        sections.find(".symtab"), RawStringTable(sections.find(".strtab"))
    ).symbols()[1]

    assert duplicate_symbol.fields()["st_info"] == symbol_type
