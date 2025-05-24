from unittest.mock import patch

import pytest
from _pytest.capture import CaptureFixture

from src.control.command import Command
from src.control.command_line import (
    HistoricalCommandLine,
    InteractiveCommandLine,
)


class ValidCommand(Command):
    def name(self) -> str:
        return "valid"

    def output(self, raw_arguments: list[str], in_json: bool = False) -> str:
        return "I am executed!"


class FailingCommand(Command):
    def name(self) -> str:
        return "failing"

    def output(self, raw_arguments: list[str], in_json: bool = False) -> str:
        raise ValueError("I am failing!")


def test_help_command(capsys: CaptureFixture[str]) -> None:
    expected_output = (
        "header                      Show executable header\n"
        "sections[--full]            List all sections\n"
        "section -n NAME[-full]      Show section by name\n"
        "text[--offset N][--size N]  Disassemble.text section\n"
        "exit                        Exit the shell\n"
    )

    with patch("builtins.input", side_effect=["help", "exit"]):
        with pytest.raises(SystemExit):
            InteractiveCommandLine(expected_output, []).run()

    assert expected_output in capsys.readouterr().out


def test_empty_input() -> None:
    with patch("builtins.input", side_effect=["", "exit"]):
        with pytest.raises(SystemExit):
            InteractiveCommandLine("", []).run()


def test_valid_command_execution(capsys: CaptureFixture[str]) -> None:
    with patch("builtins.input", side_effect=["valid", "exit"]):
        with pytest.raises(SystemExit):
            InteractiveCommandLine("", [ValidCommand()]).run()

    assert "I am executed!" in capsys.readouterr().out


def test_unknown_command_full_message(capsys: CaptureFixture[str]) -> None:
    with patch("builtins.input", side_effect=["unknown", "exit"]):
        with pytest.raises(SystemExit):
            InteractiveCommandLine("Hint", [ValidCommand()]).run()

    output = capsys.readouterr().out
    assert "Unknown command 'unknown'" in output
    assert "Type 'help' to see available commands" in output


def test_failing_command_execution(capsys: CaptureFixture[str]) -> None:
    with patch("builtins.input", side_effect=["failing", "exit"]):
        with pytest.raises(SystemExit):
            InteractiveCommandLine("", [FailingCommand()]).run()

    assert "I am failing!" in capsys.readouterr().out


def test_historical_command_execution(capsys: CaptureFixture[str]) -> None:
    with patch("builtins.input", side_effect=["valid", "exit"]):
        with pytest.raises(SystemExit):
            HistoricalCommandLine(
                InteractiveCommandLine("", [ValidCommand()])
            ).run()

    assert "I am executed!" in capsys.readouterr().out
