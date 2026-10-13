"""Utility functions for Android RE Toolkit."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

# Common secret patterns (for educational / research detection)
SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})", "API Key"),
    (r"(?i)(secret[_-]?key|secret)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})", "Secret Key"),
    (r"(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-.]{20,})", "Access Token"),
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{6,})", "Password"),
    (r"(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*['\"]?([A-Z0-9]{16,})", "AWS Access Key"),
    (r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{30,})", "AWS Secret Key"),
    (r"(?i)(firebase[_-]?api[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{30,})", "Firebase API Key"),
    (r"(?i)(google[_-]?api[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{30,})", "Google API Key"),
    (r"https?://[^\s\"']+", "URL"),
    (r"(?i)(Bearer\s+[a-zA-Z0-9\-._~+/]+=*)", "Bearer Token"),
]


def file_hashes(path: str | Path) -> dict[str, str]:
    """Calculate MD5 and SHA256 of a file."""
    path = Path(path)
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size": path.stat().st_size,
    }


def find_secrets(text: str) -> list[dict[str, str]]:
    """Scan text for potential secrets using regex patterns."""
    findings = []
    seen = set()

    for pattern, label in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            value = match.group(0)
            # Avoid duplicates and very common false positives
            if value in seen or len(value) < 8:
                continue
            if "http://schemas.android.com" in value:
                continue
            seen.add(value)
            findings.append({
                "type": label,
                "value": value[:120] + ("..." if len(value) > 120 else ""),
                "full_match": value,
            })

    return findings


def safe_get(obj: Any, *keys, default=None):
    """Safely traverse nested objects/dicts."""
    current = obj
    for key in keys:
        try:
            if isinstance(current, dict):
                current = current.get(key, default)
            else:
                current = getattr(current, key, default)
            if current is None:
                return default
        except Exception:
            return default
    return current


def is_tool_available(tool_name: str) -> bool:
    """Check if an external binary is available in PATH."""
    from shutil import which
    return which(tool_name) is not None


def ensure_dir(path: str | Path) -> Path:
    """Create directory if it does not exist."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p
