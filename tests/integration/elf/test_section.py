import pytest

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
def raw_data(request) -> bytearray:
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
def test_returning_section_names(raw_data, sections):
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
def test_returning_section_names_on_stripped_binary(raw_data):
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
def test_finding_section(raw_data, sections):
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
def test_raising_on_finding_nonexistent_section(raw_data, sections):
    with pytest.raises(ValueError, match="Section '.nonexistent' not found"):
        assert sections(raw_data).find(".nonexistent")


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_name_offset_if_shstrtab_is_not_present(raw_data):
    expected_string_offset = "27"

    offset = RawExecutableHeader(raw_data).fields()["e_shoff"]

    assert (
        RawSection(raw_data, RawSectionHeader(raw_data, offset + 64)).name()
        == expected_string_offset
    )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_shstrtab_name_by_index(raw_data):
    executable_header = RawExecutableHeader(raw_data)
    section_headers = RawSectionHeaders(raw_data, executable_header)

    shstrtab = RawStringTable(
        RawSection(
            raw_data,
            section_headers.all()[executable_header.fields()["e_shstrndx"]],
        )
    )
    assert shstrtab.name_by_index(17) == ".shstrtab"


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_returning_text_disassembly(raw_data):
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

    for section in sections.all():
        if section.name() == ".text":
            assert (
                RawDisassembly(section).instructions()[: len(expected_output)]
                == expected_output
            )


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_disassembling_not_executable_section(raw_data):
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
def test_returning_symbol_table(raw_data):
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

    symbol = ValidatedSymbolTable(
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
def test_symbol_change_reflects_in_raw_data(raw_data):
    executable_header = RawExecutableHeader(raw_data)
    sections = RawSections(
        raw_data,
        RawSectionHeaders(raw_data, executable_header),
        executable_header,
    )

    symtab = sections.find(".symtab")
    strtab = sections.find(".strtab")

    symbol = ValidatedSymbol(
        RawSymbolTable(symtab, RawStringTable(strtab)).symbols()[1]
    )

    fields = symbol.fields()

    assert fields["st_info"] != (Symbol.STB_GLOBAL << 4) | Symbol.STT_FUNC

    fields["st_info"] = (Symbol.STB_GLOBAL << 4) | Symbol.STT_FUNC

    symbol.change(fields)

    symbol = RawSymbolTable(symtab, RawStringTable(strtab)).symbols()[1]
    assert symbol.fields()["st_info"] == fields["st_info"]


@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_returning_fields_of_unprocessable_binary(raw_data):
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
def test_raising_on_changing_fields_with_missing_field(raw_data):
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
        ("st_info", 254, "Invalid value for st_info"),
        ("st_other", 256, "Unable to process data"),
        ("st_shndx", 999999, "Invalid value for st_shndx"),
        ("unknown", 123, "Unknown field unknown"),
    ],
)
@pytest.mark.parametrize(
    "raw_data", ["tests/samples/binaries/binary"], indirect=True
)
def test_raising_on_changing_symbol_with_invalid_value(
    raw_data, field, invalid_value, error
):
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

    with pytest.raises(ValueError, match=error):
        ValidatedSymbol(symbol).change(fields)
