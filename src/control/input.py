from abc import ABC, abstractmethod


class File(ABC):
    @abstractmethod
    def raw_data(self) -> bytearray:
        pass  # pragma: no cover


class ArgvFile(File):
    def __init__(self, argv: list, index: int = 1):
        self.__argv = argv
        self.__index = index

    def raw_data(self) -> bytearray:
        with open(self.__argv[self.__index], "rb") as file:
            return bytearray(file.read())


class HandledArgvFile(File):
    def __init__(self, origin: ArgvFile, hint: str):
        self.__origin = origin
        self.__hint = hint

    def raw_data(self) -> bytearray:
        try:
            return self.__origin.raw_data()
        except IndexError:
            message = self.__hint
        except OSError as error:
            message = f"Failed to load file: '{error.strerror}'"

        raise ValueError(message)
