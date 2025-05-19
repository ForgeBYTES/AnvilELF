import shutil
from pathlib import Path
from typing import Generator

import pytest


@pytest.fixture
def prepare_temporary_binaries() -> Generator[None, None, None]:
    original_path = Path("tests/samples/binaries")
    temporary_path = Path("tests/samples/temporary_binaries")

    for file in original_path.iterdir():
        if file.is_file():  # pragma: no cover
            shutil.copy(file, temporary_path)

    yield

    for file in temporary_path.iterdir():
        if file.name != ".gitkeep":
            file.unlink()
