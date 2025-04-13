import argparse
from abc import ABC, abstractmethod

from src.elf.executable_header import ExecutableHeader
from src.elf.section import DisassembledSection, Sections
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
        PrintableSections(self.__sections, full=arguments.full).print()

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
                    DisassembledSection(section),
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


class DisassemblyCommand(Command):
    def __init__(
        self, sections: Sections, command_name: str, section_name: str
    ):
        self._sections = sections
        self.__command_name = command_name
        self.__section_name = section_name

    def name(self) -> str:
        return self.__command_name

    def execute(self, raw_arguments: list[str]) -> None:
        for section in self._sections.all():
            if section.name() == self.__section_name:
                PrintableDisassemblable(DisassembledSection(section)).print()
                return
        raise ValueError(
            f"Section '{self.__section_name}' not found"
        )  # pragma: no cover


class PltCommand(DisassemblyCommand):
    def __init__(self, sections: Sections):
        super().__init__(sections, "plt", ".plt")


class InitCommand(DisassemblyCommand):
    def __init__(self, sections: Sections):
        super().__init__(sections, "init", ".init")


class FiniCommand(DisassemblyCommand):
    def __init__(self, sections: Sections):
        super().__init__(sections, "fini", ".fini")
