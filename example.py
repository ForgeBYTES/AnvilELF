from typing import cast

from src.elf.executable_header import (
    RawExecutableHeader,
    ValidatedExecutableHeader,
)
from src.elf.section import RawSections, RawShstrtabSection
from src.elf.section_header import RawSectionHeaders, ValidatedSectionHeaders

with open("tests/samples/binaries/stripped-binary", "rb") as f:
    raw_data = bytearray(f.read())

# Executable Header
executable_header = ValidatedExecutableHeader(RawExecutableHeader(raw_data))
print(executable_header)

# Section Headers
section_headers = ValidatedSectionHeaders(
    RawSectionHeaders(raw_data, executable_header)
)
for header in section_headers.all():
    print(header)

# Sections
sections = RawSections(
    raw_data,
    section_headers,
    executable_header,
)
for section in sections.all():
    print(section.name())

# .shstrtab section
shstrtab = cast(RawShstrtabSection, sections.by_name(".shstrtab"))

print(shstrtab.index_by_name(".shstrtab"))
print(shstrtab.name_by_index(17))

# .bss section
text = sections.by_name(".bss")
print(text)
