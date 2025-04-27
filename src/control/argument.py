import argparse
from typing import Never


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise ValueError(message.capitalize())
