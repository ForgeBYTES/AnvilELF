import atexit
import os
import readline
from abc import ABC, abstractmethod

from src.control.command import Command


class CommandLine(ABC):
    @abstractmethod
    def run(self):
        pass


class InteractiveCommandLine(CommandLine):
    def __init__(self, hint: str, commands: list[Command]):
        self.__hint = hint
        self.__commands = commands
        self.__running = True

    def run(self):
        while self.__running:
            try:
                self.__execute(*self.__input())
            except ValueError as error:
                print(f"[Error] {error}")
            except KeyboardInterrupt:
                break

    def __input(self) -> tuple[str, list[str]]:
        arguments = input("anvil> ").strip().split()
        return arguments[0], arguments[1:]

    def __execute(self, command_name: str, arguments: list[str]) -> None:
        match command_name:
            case "exit":
                self.__running = False
            case "help":
                print(self.__hint)
            case _:
                for command in self.__commands:
                    if command_name == command.name():
                        command.execute(arguments)
                        return
                print(
                    f"[Error] Unknown command '{command_name}'",
                    "[Info] Type 'help' to see available commands",
                    sep="\n",
                )


class HistoricalCommandLine(CommandLine):
    __HISTORY = "~/.anvil_history"

    def __init__(self, origin: CommandLine):
        self.__origin = origin

    def run(self):
        self.__setup_history(self.__HISTORY)
        self.__origin.run()

    def __setup_history(self, history: str) -> None:
        path = os.path.expanduser(history)
        try:
            readline.read_history_file(path)
        except FileNotFoundError:
            pass
        atexit.register(readline.write_history_file, path)
