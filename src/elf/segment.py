from abc import ABC, abstractmethod

from src.elf.program_header import ProgramHeader, ProgramHeaders


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
                fields["p_offset"] : fields["p_offset"]  # noqa: E203
                + fields["p_filesz"]
            ]
        raise ValueError("Exceeded segment size")

    def replace(self, data: bytes) -> None:
        fields = self.__header.fields()
        if not (
            self.__is_in_range(fields) and self.__is_valid_size(data, fields)
        ):
            raise ValueError("Invalid segment size")
        self.__raw_data[
            fields["p_offset"] : fields["p_offset"]  # noqa: E203
            + fields["p_filesz"]
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
