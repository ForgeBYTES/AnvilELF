import struct
from abc import ABC, abstractmethod

from src.elf.program_header import ProgramHeader, ProgramHeaders
from src.elf.validation import Validatable


class Segment(ABC):
    @abstractmethod
    def header(self) -> dict[str, int]:
        pass  # pragma: no cover

    @abstractmethod
    def raw_data(self) -> memoryview:
        pass  # pragma: no cover

    @abstractmethod
    def replace(self, data: bytes) -> None:
        pass  # pragma: no cover

    @abstractmethod
    def type(self) -> str:
        pass  # pragma: no cover


class Segments(ABC):
    @abstractmethod
    def all(self) -> list[Segment]:
        pass  # pragma: no cover

    @abstractmethod
    def occurrence(self, p_type: int, p_flags: int | None = None) -> Segment:
        pass  # pragma: no cover


class DynamicEntry(ABC):
    ENTRY_SIZE = 16
    FIELDS = ["d_tag", "d_un"]

    DT_NULL = 0
    DT_NEEDED = 1
    DT_PLTRELSZ = 2
    DT_PLTGOT = 3
    DT_HASH = 4
    DT_STRTAB = 5
    DT_SYMTAB = 6
    DT_RELA = 7
    DT_RELASZ = 8
    DT_RELAENT = 9
    DT_STRSZ = 10
    DT_SYMENT = 11
    DT_INIT = 12
    DT_FINI = 13
    DT_SONAME = 14
    DT_RPATH = 15
    DT_SYMBOLIC = 16
    DT_REL = 17
    DT_RELSZ = 18
    DT_RELENT = 19
    DT_PLTREL = 20
    DT_DEBUG = 21
    DT_TEXTREL = 22
    DT_JMPREL = 23
    DT_BIND_NOW = 24
    DT_INIT_ARRAY = 25
    DT_FINI_ARRAY = 26
    DT_INIT_ARRAYSZ = 27
    DT_FINI_ARRAYSZ = 28
    DT_RUNPATH = 29
    DT_FLAGS = 30
    DT_PREINIT_ARRAY = 32
    DT_PREINIT_ARRAYSZ = 33
    DT_MAXPOSTAGS = 34

    # fmt: off
    TAGS = [
        DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_PLTGOT, DT_HASH, DT_STRTAB,
        DT_SYMTAB, DT_RELA, DT_RELASZ, DT_RELAENT, DT_STRSZ, DT_SYMENT,
        DT_INIT, DT_FINI, DT_SONAME, DT_RPATH, DT_SYMBOLIC, DT_REL,
        DT_RELSZ, DT_RELENT, DT_PLTREL, DT_DEBUG, DT_TEXTREL, DT_JMPREL,
        DT_BIND_NOW, DT_INIT_ARRAY, DT_FINI_ARRAY, DT_INIT_ARRAYSZ,
        DT_FINI_ARRAYSZ, DT_RUNPATH, DT_FLAGS, DT_PREINIT_ARRAY,
        DT_PREINIT_ARRAYSZ, DT_MAXPOSTAGS,
    ]
    # fmt: on

    DT_LOOS = 0x6000000D
    DT_HIPROC = 0x7FFFFFFF

    @abstractmethod
    def fields(self) -> dict[str, int]:
        pass  # pragma: no cover

    @abstractmethod
    def change(self, fields: dict[str, int]) -> None:
        pass  # pragma: no cover


class Dynamic(ABC):
    @abstractmethod
    def all(self) -> list[DynamicEntry]:
        pass  # pragma: no cover


class RawSegment(Segment):
    def __init__(self, raw_data: bytearray, header: ProgramHeader):
        self.__raw_data = raw_data
        self.__header = header

    def header(self) -> dict[str, int]:
        return self.__header.fields()

    def raw_data(self) -> memoryview:
        fields = self.__header.fields()
        if self.__is_in_range(fields):
            return memoryview(self.__raw_data)[
                fields["p_offset"] : fields["p_offset"] + fields["p_filesz"]
            ]
        raise ValueError("Exceeded segment size")

    def replace(self, data: bytes) -> None:
        fields = self.__header.fields()
        if not (
            self.__is_in_range(fields) and self.__is_valid_size(data, fields)
        ):
            raise ValueError("Invalid segment size")
        self.__raw_data[
            fields["p_offset"] : fields["p_offset"] + fields["p_filesz"]
        ] = data

    def type(self) -> str:
        return str(self.__header.fields()["p_type"])

    def __is_in_range(self, fields: dict[str, int]) -> bool:
        return fields["p_offset"] + fields["p_filesz"] <= len(self.__raw_data)

    def __is_valid_size(self, data: bytes, fields: dict[str, int]) -> bool:
        return len(data) == fields["p_filesz"]


class RawSegments(Segments):
    def __init__(self, raw_data: bytearray, program_headers: ProgramHeaders):
        self.__raw_data = raw_data
        self.__program_headers = program_headers

    def all(self) -> list[Segment]:
        return [
            RawSegment(self.__raw_data, program_header)
            for program_header in self.__program_headers.all()
        ]

    def occurrence(self, p_type: int, p_flags: int | None = None) -> Segment:
        for segment in self.all():
            header = segment.header()
            if header["p_type"] == p_type and (
                p_flags is None or header["p_flags"] == p_flags
            ):
                return segment
        raise ValueError(
            f"No segment found with p_type {p_type}"
            + (f" and p_flags 0x{p_flags:X}" if p_flags else "")
        )


class RawDynamicEntry(DynamicEntry):
    __STRUCT_FORMAT = "<qQ"

    def __init__(self, raw_data: memoryview, offset: int):
        self.__raw_data = raw_data
        self.__offset = offset

    def fields(self) -> dict[str, int]:
        try:
            return dict(
                zip(
                    self.FIELDS,
                    struct.unpack_from(
                        self.__STRUCT_FORMAT, self.__raw_data, self.__offset
                    ),
                )
            )
        except struct.error:
            raise ValueError("Unable to process data")

    def change(self, fields: dict[str, int]) -> None:
        try:
            self.__raw_data[
                self.__offset : self.__offset + self.ENTRY_SIZE
            ] = struct.pack(
                self.__STRUCT_FORMAT, *(fields[field] for field in self.FIELDS)
            )
        except (KeyError, struct.error):
            raise ValueError("Unable to process data")


class RawDynamic(Dynamic):
    def __init__(self, segment: Segment):
        self.__segment = segment

    def all(self) -> list[DynamicEntry]:
        raw_data = self.__segment.raw_data()
        return [
            RawDynamicEntry(raw_data, offset)
            for offset in range(0, len(raw_data), RawDynamicEntry.ENTRY_SIZE)
        ]


class ValidatedDynamicEntry(DynamicEntry, Validatable):
    def __init__(self, origin: DynamicEntry):
        self.__origin = origin

    def fields(self) -> dict[str, int]:
        return self.__origin.fields()

    def change(self, fields: dict[str, int]) -> None:
        self.__validate(fields)
        return self.__origin.change(fields)

    def validate(self) -> None:
        self.__validate(self.__origin.fields())

    def __validate(self, fields: dict[str, int]) -> None:
        invalid_fields: dict[str, int] = {}
        for field, value in fields.items():
            match field:
                case "d_tag":
                    if not (
                        value in DynamicEntry.TAGS
                        or (
                            DynamicEntry.DT_LOOS
                            <= value
                            <= DynamicEntry.DT_HIPROC
                        )
                    ):
                        invalid_fields[field] = value
                case _:
                    if field not in DynamicEntry.FIELDS:
                        invalid_fields[field] = value

        if invalid_fields:
            raise ValueError(
                self.error_message("Dynamic entry", invalid_fields)
            )


class ValidatedDynamic(Dynamic, Validatable):
    def __init__(self, origin: Dynamic):
        self.__origin = origin

    def all(self) -> list[DynamicEntry]:
        return [ValidatedDynamicEntry(entry) for entry in self.__origin.all()]

    def validate(self) -> None:
        for entry in self.__origin.all():
            ValidatedDynamicEntry(entry).validate()
