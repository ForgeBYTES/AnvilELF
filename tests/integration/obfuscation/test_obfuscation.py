import shutil
import subprocess
from pathlib import Path
from typing import Generator

import pytest

from src.elf.binary import RawBinary
from src.elf.executable_header import ExecutableHeader
from src.elf.section import Sections
from src.elf.section_header import SectionHeaders
from src.obfuscation.obfuscation import HeaderlessBinary


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


def test_removing_binary_section_headers(
    prepare_temporary_binaries: Generator[None, None, None],
) -> None:
    path = "tests/samples/temporary_binaries/binary"

    original_data = RawBinary(path).raw_data()

    assert (
        "There are 31 section headers"
        in subprocess.run(
            ["readelf", "-S", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    )

    headerless_binary = HeaderlessBinary(RawBinary(path))
    headerless_binary.save()

    assert headerless_binary.raw_data() != original_data

    assert (
        "There are no sections in this file"
        in subprocess.run(
            ["readelf", "-S", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    )

    output = subprocess.run(
        [f"./{path}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert output.returncode == 0
    assert "Hello world!" in output.stdout.strip()


def test_returning_components_by_headerless_binary(
    prepare_temporary_binaries: Generator[None, None, None],
) -> None:
    expected_executable_header = {
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
        "e_shoff": 0,
        "e_flags": 0,
        "e_ehsize": 64,
        "e_phentsize": 56,
        "e_phnum": 13,
        "e_shentsize": 0,
        "e_shnum": 0,
        "e_shstrndx": 0,
    }

    path = "tests/samples/temporary_binaries/binary"

    headerless_binary = HeaderlessBinary(RawBinary(path))
    executable_header, section_headers, sections = (
        headerless_binary.components()
    )

    assert isinstance(executable_header, ExecutableHeader)
    assert executable_header.fields() == expected_executable_header

    assert isinstance(section_headers, SectionHeaders)
    with pytest.raises(
        ValueError,
        match="Section header table metadata is missing or incomplete",
    ):
        section_headers.all()

    assert isinstance(sections, Sections)
    with pytest.raises(
        ValueError,
        match="Section header table metadata is missing or incomplete",
    ):
        sections.all()
