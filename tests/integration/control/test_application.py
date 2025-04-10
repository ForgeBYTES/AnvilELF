import subprocess


def test_application_returns_usage_on_no_args():
    result = subprocess.run(
        ["python", "main.py"], capture_output=True, text=True
    )
    assert result.returncode == 1
    assert "Usage: python main.py <binary>" in result.stdout


def test_application_returns_error_on_nonexistent_file():
    result = subprocess.run(
        ["python", "main.py", "nonexistent"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "Failed to load file: 'No such file or directory'" in result.stdout


def test_application_runs():
    result = subprocess.run(
        ["python", "main.py", "tests/samples/binaries/binary"],
        capture_output=True,
        text=True,
    )
    assert result.stdout.endswith("anvil> ")
