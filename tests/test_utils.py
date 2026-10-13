"""Basic unit tests for utility functions."""

from apk_re.utils import find_secrets, file_hashes
from pathlib import Path
import tempfile


def test_find_secrets_api_key():
    text = 'api_key = "AIzaSyDummyKeyForTesting1234567890"'
    findings = find_secrets(text)
    assert len(findings) >= 1
    assert any("API" in f["type"] or "Key" in f["type"] for f in findings)


def test_find_secrets_url():
    text = "https://api.example.com/v1/endpoint"
    findings = find_secrets(text)
    assert any(f["type"] == "URL" for f in findings)


def test_file_hashes():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"hello world")
        path = f.name

    hashes = file_hashes(path)
    assert "md5" in hashes
    assert "sha256" in hashes
    assert hashes["size"] == 11
    Path(path).unlink()
