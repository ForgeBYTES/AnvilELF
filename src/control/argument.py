import argparse
from typing import Never


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise ValueError(message.capitalize())

    def int(self, value: str) -> int:
        try:
            return int(value, 0)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"invalid integer value: '{value}'"
            )

    def bytes(self, value: str) -> bytes:
        try:
            return (
                bytes(value, "utf-8").decode("unicode_escape").encode("latin1")
            )
        except (UnicodeDecodeError, UnicodeEncodeError):
            raise argparse.ArgumentTypeError(f"invalid byte string: '{value}'")
