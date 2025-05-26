import subprocess
from typing import Generator

import pytest

from src.elf.binary import RawBinary
from src.elf.executable_header import ExecutableHeader
from src.elf.section import Sections
from src.elf.section_header import SectionHeaders
from src.obfuscation.obfuscation import HeaderlessBinary


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
    headerless_binary.obfuscate()
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
    headerless_binary.obfuscate()
    executable_header, section_headers, sections, program_headers, segments = (
        headerless_binary.components()
    )

    assert isinstance(executable_header, ExecutableHeader)
    assert executable_header.fields() == expected_executable_header

    assert isinstance(section_headers, SectionHeaders)
    with pytest.raises(
        ValueError,
        match="Section header table metadata is missing or invalid",
    ):
        section_headers.all()

    assert isinstance(sections, Sections)
    with pytest.raises(
        ValueError,
        match="Section header table metadata is missing or invalid",
    ):
        sections.all()
