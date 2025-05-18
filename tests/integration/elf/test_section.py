import re
from typing import Callable

import pytest
from _pytest.fixtures import FixtureRequest

from src.elf.executable_header import (
    RawExecutableHeader,
    ValidatedExecutableHeader,
)
from src.elf.section import (
    RawDisassembly,
    RawSection,
    RawSections,
    RawStringTable,
    RawSymbol,
    RawSymbolTable,
    Symbol,
    ValidatedSymbol,
    ValidatedSymbolTable,
)
from src.elf.section_header import (
    RawSectionHeader,
    RawSectionHeaders,
    ValidatedSectionHeaders,
)


@pytest.fixture
def raw_data(request: FixtureRequest) -> bytearray:
    with open(request.param, "rb") as binary:
        return bytearray(binary.read())


@pytest.mark.parametrize(
    "sections",
    [
        lambda raw_data: RawSections(
            raw_data,
            RawSectionHeaders(raw_data, RawExecutableHeader(raw_data)),
            RawExecutableHeader(raw_data),
        ),
        lambda raw_data: RawSections(
            raw_data,
            ValidatedSectionHeaders(
                RawSectionHeaders(raw_data, RawExecutableHeader(raw_data))
            ),
            ValidatedExecutableHeader(RawExecutableHeader(raw_data)),
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_returning_section_names(
    raw_data: bytearray, sections: Callable[[bytearray], RawSections]
) -> None:
    # fmt: off
    expected_section_names = [
        "", ".interp", ".note.gnu.property", ".note.gnu.build-id",
        ".note.ABI-tag", ".gnu.hash", ".dynsym", ".dynstr",
        ".gnu.version", ".gnu.version_r", ".rela.dyn", ".rela.plt",
        ".init", ".plt", ".plt.got", ".plt.sec",
        ".text", ".fini", ".rodata", ".eh_frame_hdr",
        ".eh_frame", ".init_array", ".fini_array", ".dynamic",
        ".got", ".data", ".bss", ".comment", ".debug_aranges",
        ".debug_info", ".debug_abbrev", ".debug_line", ".debug_str",
        ".debug_line_str", ".debug_loclists", ".debug_rnglists", ".symtab",
        ".strtab", ".shstrtab",
    ]
    # fmt: on
    assert [
        section.name() for section in sections(raw_data).all()
    ] == expected_section_names


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_returning_section_names_on_stripped_binary(
    raw_data: bytearray,
) -> None:
    # fmt: off
    expected_section_names = [
        "", ".interp", ".note.gnu.property", ".note.gnu.build-id",
        ".note.ABI-tag", ".gnu.hash", ".dynsym", ".dynstr",
        ".gnu.version", ".gnu.version_r", ".rela.dyn", ".rela.plt",
        ".init", ".plt", ".plt.got", ".plt.sec",
        ".text", ".fini", ".rodata", ".eh_frame_hdr",
        ".eh_frame", ".init_array", ".fini_array", ".dynamic",
        ".got", ".data", ".bss", ".comment", ".shstrtab",
    ]
    # fmt: on

    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, RawExecutableHeader(raw_data)),
        RawExecutableHeader(raw_data),
    )

    assert [
        section.name() for section in sections.all()
    ] == expected_section_names


@pytest.mark.parametrize(
    "sections",
    [
        lambda raw_data: RawSections(
            raw_data,
            RawSectionHeaders(raw_data, RawExecutableHeader(raw_data)),
            RawExecutableHeader(raw_data),
        ),
        lambda raw_data: RawSections(
            raw_data,
            ValidatedSectionHeaders(
                RawSectionHeaders(raw_data, RawExecutableHeader(raw_data))
            ),
            ValidatedExecutableHeader(RawExecutableHeader(raw_data)),
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary-2"], indirect=True
)
def test_finding_section(
    raw_data: bytearray, sections: Callable[[bytearray], RawSections]
) -> None:
    assert sections(raw_data).find(".text").name() == ".text"


@pytest.mark.parametrize(
    "sections",
    [
        lambda raw_data: RawSections(
            raw_data,
            RawSectionHeaders(raw_data, RawExecutableHeader(raw_data)),
            RawExecutableHeader(raw_data),
        ),
        lambda raw_data: RawSections(
            raw_data,
            ValidatedSectionHeaders(
                RawSectionHeaders(raw_data, RawExecutableHeader(raw_data))
            ),
            ValidatedExecutableHeader(RawExecutableHeader(raw_data)),
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_finding_nonexistent_section(
    raw_data: bytearray, sections: Callable[[bytearray], RawSections]
) -> None:
    with pytest.raises(ValueError, match="Section '.nonexistent' not found"):
        assert sections(raw_data).find(".nonexistent")


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_name_offset_if_shstrtab_is_not_present(
    raw_data: bytearray,
) -> None:
    expected_string_offset = "27"

    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    assert (
        RawSection(raw_data, RawSectionHeader(raw_data, offset + 64)).name()
        == expected_string_offset
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_shstrtab_name_by_index(raw_data: bytearray) -> None:
    executable_header = RawExecutableHeader(raw_data)
    section_headers = RawSectionHeaders(raw_data, executable_header)

    shstrtab = RawStringTable(
        RawSection(
            raw_data,
            section_headers.all()[executable_header.fields()["e_shstrndx"]],
        )
    )
    assert shstrtab.name_by_offset(17) == ".shstrtab"


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_text_disassembly(raw_data: bytearray) -> None:
    expected_output = [
        "00001060: endbr64",
        "00001064: xor ebp, ebp",
        "00001066: mov r9, rdx",
        "00001069: pop rsi",
        "0000106a: mov rdx, rsp",
        "0000106d: and rsp, 0xfffffffffffffff0",
        "00001071: push rax",
        "00001072: push rsp",
        "00001073: xor r8d, r8d",
        "00001076: xor ecx, ecx",
        "00001078: lea rdi, [rip + 0xca]",
        "0000107f: call qword ptr [rip + 0x2f53]",
        "00001085: hlt",
    ]

    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    assert (
        RawDisassembly(sections.find(".text")).instructions()[
            : len(expected_output)
        ]
        == expected_output
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_disassembling_not_executable_section(
    raw_data: bytearray,
) -> None:
    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    with pytest.raises(ValueError, match="Section is not executable"):
        RawDisassembly(sections.find(".bss")).instructions()


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_symbol_table(raw_data: bytearray) -> None:
    expected_name = "_init"
    expected_fields = {
        "st_name": 473,
        "st_info": 18,
        "st_other": 2,
        "st_shndx": 12,
        "st_value": 4096,
        "st_size": 0,
    }
    expected_type = 2
    expected_visibility = 2
    expected_bind = 1

    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    symtab = sections.find(".symtab")
    strtab = sections.find(".strtab")

    symbol: Symbol = ValidatedSymbolTable(
        RawSymbolTable(symtab, RawStringTable(strtab))
    ).symbols()[-1]

    assert symbol.name() == expected_name
    assert symbol.fields() == expected_fields
    assert symbol.type() == expected_type
    assert symbol.visibility() == expected_visibility
    assert symbol.bind() == expected_bind


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_symbol_change_reflects_in_raw_data(raw_data: bytearray) -> None:
    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    symtab = sections.find(".symtab")
    strtab = sections.find(".strtab")

    validated_symbol = ValidatedSymbol(
        RawSymbolTable(symtab, RawStringTable(strtab)).symbols()[1]
    )

    fields = validated_symbol.fields()

    assert fields["st_info"] != (Symbol.STB_GLOBAL << 4) | Symbol.STT_FUNC

    fields["st_info"] = (Symbol.STB_GLOBAL << 4) | Symbol.STT_FUNC

    validated_symbol.change(fields)

    raw_symbol = RawSymbolTable(symtab, RawStringTable(strtab)).symbols()[1]
    assert raw_symbol.fields()["st_info"] == fields["st_info"]


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_returning_symbol_fields_of_unprocessable_binary(
    raw_data: bytearray,
) -> None:
    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    with pytest.raises(ValueError, match="Unable to process data"):
        RawSymbol(
            memoryview(bytearray(b"unprocessable data")),
            24,
            RawStringTable(sections.find(".symtab")),
        ).fields()


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_symbol_fields_with_missing_field(
    raw_data: bytearray,
) -> None:
    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    symbol = RawSymbolTable(
        sections.find(".symtab"), RawStringTable(sections.find(".strtab"))
    ).symbols()[1]

    fields = symbol.fields()
    fields["st_info"] = (Symbol.STB_GLOBAL << 4) | Symbol.STT_FUNC

    del fields["st_value"]

    with pytest.raises(ValueError, match="Unable to process data"):
        symbol.change(fields)


@pytest.mark.parametrize(
    "field, invalid_value, error",
    [
        (
            "st_info",
            254,
            "Symbol (Scrt1.o) contains invalid values:\n  st_info=254",
        ),
        ("st_other", 256, "Unable to process data"),
        (
            "st_shndx",
            999999,
            "Symbol (Scrt1.o) contains invalid values:\n  st_shndx=999999",
        ),
        (
            "unknown",
            123,
            "Symbol (Scrt1.o) contains invalid values:\n  unknown=123",
        ),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_symbol_with_invalid_value(
    raw_data: bytearray, field: str, invalid_value: int, error: str
) -> None:
    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    symbol = RawSymbolTable(
        sections.find(".symtab"),
        RawStringTable(sections.find(".strtab")),
    ).symbols()[1]

    fields = symbol.fields()
    fields[field] = invalid_value

    with pytest.raises(ValueError, match=re.escape(error)):
        ValidatedSymbol(symbol).change(fields)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_multiple_symbol_fields_with_invalid_values(
    raw_data: bytearray,
) -> None:
    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    symbol = RawSymbolTable(
        sections.find(".symtab"),
        RawStringTable(sections.find(".strtab")),
    ).symbols()[1]

    fields = symbol.fields()
    fields["st_info"] = 254
    fields["st_shndx"] = 999999
    fields["unknown"] = 123

    with pytest.raises(
        ValueError,
        match=re.escape(
            "Symbol (Scrt1.o) contains invalid values:\n"
            "  st_info=254\n"
            "  st_shndx=999999\n"
            "  unknown=123"
        ),
    ):
        ValidatedSymbol(symbol).change(fields)


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_replacing_shstrtab(raw_data: bytearray) -> None:
    data = (
        b"\x00.shstrtab\x00.interp\x00.note.gnu.property\x00"
        b".note.gnu.build-id\x00.note.ABI-tag\x00.gnu.hash\x00"
        b".dynsym\x00.dynstr\x00.gnu.version\x00.gnu.version_r\x00"
        b".rela.dyn\x00.rela.plt\x00.init\x00.plt.got\x00.plt.sec\x00"
        b".code\x00.fini\x00.rodata\x00.eh_frame_hdr\x00.eh_frame\x00"
        b".init_array\x00.fini_array\x00.dynamic\x00.data\x00.bss\x00"
        b".comment\x00"
    )

    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    text_data = sections.find(".text").raw_data().tobytes()

    sections.find(".shstrtab").replace(data)

    assert sections.find(".code").raw_data().tobytes() == text_data


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_raising_on_replacing_section_data_with_invalid_size(
    raw_data: bytearray,
) -> None:
    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    with pytest.raises(ValueError, match="Invalid section size"):
        sections.find(".shstrtab").replace(b"invalid size")


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/stripped-binary"], indirect=True
)
def test_raising_on_returning_section_data_with_exceeding_size(
    raw_data: bytearray,
) -> None:
    exceeding_size = len(raw_data)

    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )
    section_header = RawSectionHeader(
        raw_data,
        sections.find(".shstrtab").header()["sh_offset"],
    )

    fields = section_header.fields()
    fields["sh_offset"] = exceeding_size
    section_header.change(fields)

    broken_section = RawSection(
        raw_data=raw_data,
        header=section_header,
        shstrtab=None,
    )

    with pytest.raises(ValueError, match="Exceeded section size"):
        broken_section.raw_data()


@pytest.mark.parametrize(
    "raw_data",
    ["tests/samples/binaries/binary-with-stripped-section-header-table-index"],
    indirect=True,
)
def test_returning_sh_name_only_on_stripped_section_header_table_index(
    raw_data: bytearray,
) -> None:
    # fmt: off
    expected_section_names = [
        "0", "27", "35", "54", "73", "87", "97", "105", "113", "126", "141",
        "151", "161", "156", "167", "176", "185", "191", "197", "205", "219",
        "229", "241", "253", "171", "262", "268", "273", "1", "9", "17",
    ]
    # fmt: on

    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, RawExecutableHeader(raw_data)),
        RawExecutableHeader(raw_data),
    )

    assert [
        section.name() for section in sections.all()
    ] == expected_section_names


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_offset_from_string_table_on_exceeding_range(
    raw_data: bytearray,
) -> None:
    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    shstrtab = sections.find(".shstrtab")

    maximum_offset = len(shstrtab.raw_data())

    assert RawStringTable(shstrtab).name_by_offset(maximum_offset) == str(
        maximum_offset
    )
