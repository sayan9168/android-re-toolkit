"""Optional decompilation helpers using external tools (jadx / apktool)."""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from .utils import is_tool_available, ensure_dir

logger = logging.getLogger(__name__)


class Decompiler:
    """Wrapper around jadx and apktool."""

    def __init__(self, apk_path: str | Path, output_dir: str | Path):
        self.apk_path = Path(apk_path)
        self.output_dir = ensure_dir(output_dir)

    def decompile_jadx(self) -> Path | None:
        """Decompile to Java source using jadx."""
        if not is_tool_available("jadx"):
            logger.warning("jadx not found in PATH. Skipping Java decompilation.")
            return None

        out = self.output_dir / "jadx_out"
        ensure_dir(out)

        cmd = [
            "jadx",
            "-d", str(out),
            "--show-bad-code",
            "--no-res",          # faster, skip resources if only code needed
            str(self.apk_path),
        ]

        logger.info("Running jadx: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                logger.error("jadx failed: %s", result.stderr[:500])
                return None
            logger.info("jadx completed → %s", out)
            return out
        except subprocess.TimeoutExpired:
            logger.error("jadx timed out")
            return None
        except Exception as e:
            logger.error("jadx error: %s", e)
            return None

    def decompile_apktool(self) -> Path | None:
        """Decode resources + smali using apktool."""
        if not is_tool_available("apktool"):
            logger.warning("apktool not found in PATH. Skipping apktool decode.")
            return None

        out = self.output_dir / "apktool_out"
        # apktool creates the directory itself

        cmd = [
            "apktool",
            "d",
            "-f",               # force
            "-o", str(out),
            str(self.apk_path),
        ]

        logger.info("Running apktool: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                logger.error("apktool failed: %s", result.stderr[:500])
                return None
            logger.info("apktool completed → %s", out)
            return out
        except subprocess.TimeoutExpired:
            logger.error("apktool timed out")
            return None
        except Exception as e:
            logger.error("apktool error: %s", e)
            return None

    def run_all(self) -> dict[str, Path | None]:
        """Run both decompilers if available."""
        return {
            "jadx": self.decompile_jadx(),
            "apktool": self.decompile_apktool(),
        }
