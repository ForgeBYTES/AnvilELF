import atexit
import os
import readline
from abc import ABC, abstractmethod

from src.control.command import Command


class CommandLine(ABC):
    @abstractmethod
    def run(self) -> None:
        pass  # pragma: no cover


class InteractiveCommandLine(CommandLine):
    def __init__(self, hint: str, commands: list[Command]):
        self.__hint = hint
        self.__commands = commands

    def run(self) -> None:
        while True:
            try:
                if not (_input := self.__input()):
                    continue
                self.__execute(*_input)
            except ValueError as error:
                print(error)
            except (KeyboardInterrupt, EOFError):
                raise SystemExit(0)

    def __input(self) -> tuple[str, list[str]] | None:
        if arguments := input("anvil> ").strip().split():
            return arguments[0], arguments[1:]
        return None

    def __execute(self, command_name: str, arguments: list[str]) -> None:
        match command_name:
            case "exit":
                raise SystemExit(0)
            case "help":
                print(self.__hint)
            case _:
                for command in self.__commands:
                    if command_name == command.name():
                        command.execute(arguments)
                        return
                print(
                    f"Unknown command '{command_name}'",
                    "Type 'help' to see available commands",
                    sep="\n",
                )


class HistoricalCommandLine(CommandLine):
    __HISTORY = "~/.anvil_history"

    def __init__(self, origin: CommandLine):
        self.__origin = origin

    def run(self) -> None:
        self.__setup_history(self.__HISTORY)
        self.__origin.run()

    def __setup_history(self, history: str) -> None:
        path = os.path.expanduser(history)
        try:
            readline.read_history_file(path)
        except FileNotFoundError:  # pragma: no cover
            pass
        atexit.register(readline.write_history_file, path)
