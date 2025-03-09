import shutil
from pathlib import Path


class TemporaryFiles:
    def __init__(self, original_path: str, temporary_path: str):
        self.__original_path = Path(original_path)
        self.__temporary_path = Path(temporary_path)

    def copy(self):
        for file in self.__original_path.iterdir():
            if file.is_file():
                shutil.copy(file, self.__temporary_path)

    def unlink(self):
        for file in self.__temporary_path.iterdir():
            if file.name != ".gitkeep":
                file.unlink()
