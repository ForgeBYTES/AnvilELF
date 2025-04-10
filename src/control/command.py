import argparse
from abc import ABC, abstractmethod

from src.elf.executable_header import ExecutableHeader
from src.elf.section import RawTextSection, Sections
from src.view.view import (
    PrintableDisassemblable,
    PrintableExecutableHeader,
    PrintableSection,
    PrintableSections,
)


class Command(ABC):
    @abstractmethod
    def name(self) -> str:
        pass  # pragma: no cover

    @abstractmethod
    def execute(self, raw_arguments: list[str]) -> None:
        pass  # pragma: no cover


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(f"Invalid arguments: {message}")


class ExecutableHeaderCommand(Command):
    __NAME = "header"

    def __init__(self, executable_header: ExecutableHeader):
        self.__executable_header = executable_header

    def name(self) -> str:
        return self.__NAME

    def execute(self, raw_arguments: list[str]) -> None:
        PrintableExecutableHeader(self.__executable_header).print()


class SectionsCommand(Command):
    __NAME = "sections"

    def __init__(self, sections: Sections):
        self.__sections = sections

    def name(self) -> str:
        return self.__NAME

    def execute(self, raw_arguments: list[str]) -> None:
        arguments = self.__argument_parser(self.__NAME).parse_args(
            raw_arguments
        )
        if arguments.full:
            for section in self.__sections.all():
                PrintableSection(section).print()
        else:
            PrintableSections(self.__sections).print()

    def __argument_parser(self, name: str) -> ArgumentParser:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-f", "--full", action="store_true")
        return parser


class SectionCommand(Command):
    __NAME = "section"

    def __init__(self, sections: Sections):
        self.__sections = sections

    def name(self) -> str:
        return self.__NAME

    def execute(self, raw_arguments: list[str]) -> None:
        arguments = self.__argument_parser(self.__NAME).parse_args(
            raw_arguments
        )
        for section in self.__sections.all():
            if section.name() == arguments.name:
                PrintableSection(section, arguments.full).print()
                return
        raise ValueError(f"Section '{arguments.name}' not found")

    def __argument_parser(self, name: str) -> ArgumentParser:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-n", "--name", required=True)
        parser.add_argument("-f", "--full", action="store_true", default=False)
        return parser


class TextCommand(Command):
    __NAME = "text"

    def __init__(self, sections: Sections):
        self.__sections = sections

    def name(self) -> str:
        return self.__NAME

    def execute(self, raw_arguments: list[str]) -> None:
        arguments = self.__argument_parser(self.__NAME).parse_args(
            raw_arguments
        )
        for section in self.__sections.all():
            if section.name() == ".text":
                PrintableDisassemblable(
                    RawTextSection(section),
                    arguments.offset,
                    arguments.size,
                ).print()
                return
        raise ValueError("Section '.text' not found")  # pragma: no cover

    def __argument_parser(self, name: str) -> ArgumentParser:
        parser = ArgumentParser(prog=name, add_help=False)
        parser.add_argument("-o", "--offset", type=int, default=0)
        parser.add_argument("-s", "--size", type=int)
        return parser
