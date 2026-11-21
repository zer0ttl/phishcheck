"""Keep developer credentials and local configuration out of offline tests."""

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolate_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run tests away from the developer's project-local .env file."""
    monkeypatch.chdir(tmp_path)
