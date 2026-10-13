"""Core APK analysis engine using androguard."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.misc import AnalyzeAPK

from .utils import file_hashes, find_secrets, safe_get

logger = logging.getLogger(__name__)


@dataclass
class ComponentInfo:
    name: str
    exported: bool = False
    permission: str | None = None
    intent_filters: list[dict] = field(default_factory=list)


@dataclass
class AnalysisResult:
    # Basic
    file_path: str = ""
    package_name: str = ""
    app_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    max_sdk: str = ""

    # Hashes & size
    md5: str = ""
    sha256: str = ""
    size_bytes: int = 0

    # Permissions
    permissions: list[str] = field(default_factory=list)
    dangerous_permissions: list[str] = field(default_factory=list)

    # Components
    activities: list[ComponentInfo] = field(default_factory=list)
    services: list[ComponentInfo] = field(default_factory=list)
    receivers: list[ComponentInfo] = field(default_factory=list)
    providers: list[ComponentInfo] = field(default_factory=list)

    # Code stats
    dex_count: int = 0
    class_count: int = 0
    method_count: int = 0
    native_libs: list[str] = field(default_factory=list)

    # Security findings
    secrets: list[dict] = field(default_factory=list)
    exported_components: list[str] = field(default_factory=list)
    has_debug_flag: bool = False
    is_debuggable: bool = False

    # Certificate
    certificate_info: dict = field(default_factory=dict)

    # Raw strings sample
    interesting_strings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Dangerous Android permissions (subset of most critical ones)
DANGEROUS_PERMS = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
}


class APKAnalyzer:
    """Main analyzer class."""

    def __init__(self, apk_path: str | Path):
        self.apk_path = Path(apk_path)
        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK not found: {self.apk_path}")
        if not self.apk_path.suffix.lower() == ".apk":
            logger.warning("File does not have .apk extension")

        self.apk: APK | None = None
        self.dx = None  # Analysis object
        self.result = AnalysisResult(file_path=str(self.apk_path))

    def analyze(self) -> AnalysisResult:
        """Run full static analysis."""
        logger.info("Starting analysis of %s", self.apk_path)

        # Basic file info
        hashes = file_hashes(self.apk_path)
        self.result.md5 = hashes["md5"]
        self.result.sha256 = hashes["sha256"]
        self.result.size_bytes = hashes["size"]

        # Load APK
        self.apk = APK(str(self.apk_path))
        self._extract_basic_info()
        self._extract_permissions()
        self._extract_components()
        self._extract_certificate()
        self._extract_native_libs()
        self._check_debuggable()

        # Deeper analysis with androguard AnalyzeAPK
        try:
            a, d, dx = AnalyzeAPK(str(self.apk_path))
            self.dx = dx
            self._analyze_code(d, dx)
        except Exception as e:
            logger.warning("Deep analysis failed (androguard): %s", e)

        # Secret scanning on all strings we collected
        all_text = "\n".join(self.result.interesting_strings)
        self.result.secrets = find_secrets(all_text)

        logger.info("Analysis complete")
        return self.result

    def _extract_basic_info(self):
        assert self.apk is not None
        self.result.package_name = self.apk.get_package() or ""
        self.result.app_name = self.apk.get_app_name() or ""
        self.result.version_name = self.apk.get_androidversion_name() or ""
        self.result.version_code = str(self.apk.get_androidversion_code() or "")
        self.result.min_sdk = str(self.apk.get_min_sdk_version() or "")
        self.result.target_sdk = str(self.apk.get_target_sdk_version() or "")
        self.result.max_sdk = str(self.apk.get_max_sdk_version() or "")

    def _extract_permissions(self):
        assert self.apk is not None
        perms = self.apk.get_permissions() or []
        self.result.permissions = sorted(set(perms))
        self.result.dangerous_permissions = sorted(
            p for p in self.result.permissions if p in DANGEROUS_PERMS
        )

    def _extract_components(self):
        assert self.apk is not None

        def process_components(names: list[str], getter_exported, getter_filters):
            items = []
            for name in names or []:
                exported = False
                try:
                    exported = bool(getter_exported(name))
                except Exception:
                    pass
                filters = []
                try:
                    filters = getter_filters(name) or []
                except Exception:
                    pass
                items.append(ComponentInfo(
                    name=name,
                    exported=exported,
                    intent_filters=filters if isinstance(filters, list) else [],
                ))
                if exported:
                    self.result.exported_components.append(name)
            return items

        self.result.activities = process_components(
            self.apk.get_activities(),
            self.apk.get_activity_exported if hasattr(self.apk, "get_activity_exported") else lambda x: False,
            lambda x: [],
        )
        self.result.services = process_components(
            self.apk.get_services(),
            lambda x: False,
            lambda x: [],
        )
        self.result.receivers = process_components(
            self.apk.get_receivers(),
            lambda x: False,
            lambda x: [],
        )
        self.result.providers = process_components(
            self.apk.get_providers(),
            lambda x: False,
            lambda x: [],
        )

        # Better exported detection via manifest
        try:
            for act in self.apk.get_activities():
                # androguard already marks some
                pass
        except Exception:
            pass

    def _extract_certificate(self):
        assert self.apk is not None
        try:
            certs = self.apk.get_certificates()
            if certs:
                cert = certs[0]
                self.result.certificate_info = {
                    "subject": str(getattr(cert, "subject", "")),
                    "issuer": str(getattr(cert, "issuer", "")),
                    "serial": str(getattr(cert, "serial_number", "")),
                    "sha1": cert.sha1.hex() if hasattr(cert, "sha1") else "",
                    "sha256": cert.sha256.hex() if hasattr(cert, "sha256") else "",
                }
        except Exception as e:
            logger.debug("Certificate extraction failed: %s", e)

    def _extract_native_libs(self):
        assert self.apk is not None
        try:
            files = self.apk.get_files()
            libs = [f for f in files if f.startswith("lib/") and f.endswith(".so")]
            self.result.native_libs = sorted(libs)
        except Exception:
            self.result.native_libs = []

    def _check_debuggable(self):
        assert self.apk is not None
        try:
            # Check android:debuggable
            self.result.is_debuggable = self.apk.get_attribute_value("application", "debuggable") in ("true", "1")
        except Exception:
            self.result.is_debuggable = False

    def _analyze_code(self, d_list, dx):
        """Analyze DEX files for classes, methods and strings."""
        class_count = 0
        method_count = 0
        strings = set()

        try:
            if not isinstance(d_list, list):
                d_list = [d_list]

            self.result.dex_count = len(d_list)

            for d in d_list:
                if d is None:
                    continue
                classes = d.get_classes() if hasattr(d, "get_classes") else []
                class_count += len(classes)
                for cls in classes:
                    methods = cls.get_methods() if hasattr(cls, "get_methods") else []
                    method_count += len(methods)

                # Collect strings
                if hasattr(d, "get_strings"):
                    for s in d.get_strings():
                        if s and len(s) > 4:
                            strings.add(s)

            self.result.class_count = class_count
            self.result.method_count = method_count

            # Keep interesting strings (limit to avoid huge reports)
            interesting = []
            for s in sorted(strings):
                lower = s.lower()
                if any(k in lower for k in (
                    "http", "api", "key", "secret", "token", "password",
                    "auth", "firebase", "aws", "google", "endpoint", "url"
                )):
                    interesting.append(s)
                if len(interesting) >= 200:
                    break

            self.result.interesting_strings = interesting[:150]

        except Exception as e:
            logger.warning("Code analysis error: %s", e)
