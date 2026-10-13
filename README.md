# Android RE Toolkit

**Professional Android APK Reverse Engineering Toolkit for Security Research**

A clean, modular, and production-ready toolkit for static analysis of Android APKs. Designed for security researchers, malware analysts, and educational purposes.

## Features

- **APK Information Extraction**
  - Package name, version, min/target SDK
  - Certificate / signature info
  - File size & hash (SHA256, MD5)

- **Manifest Analysis**
  - Permissions (dangerous, normal, custom)
  - Activities, Services, Receivers, Providers
  - Intent filters & exported components
  - Deep link / scheme detection

- **Code & String Analysis**
  - Hardcoded secrets detection (API keys, tokens, passwords, URLs)
  - Interesting strings extraction
  - Native library (.so) listing
  - Dex class count & basic stats

- **Decompilation Support**
  - Optional jadx integration (Java decompilation)
  - Optional apktool integration (smali + resources)

- **Report Generation**
  - Beautiful HTML report
  - Machine-readable JSON report
  - Console summary

- **Extra**
  - Docker support
  - CLI interface
  - GitHub Actions CI

## Requirements

- Python 3.10+
- Optional external tools (for full power):
  - [jadx](https://github.com/skylot/jadx)
  - [apktool](https://ibotpeaches.github.io/Apktool/)

## Installation

```bash
# Clone
git clone https://github.com/sayan9168/android-re-toolkit.git
cd android-re-toolkit

# Install
pip install -e .

# Or with Docker
docker build -t android-re-toolkit .
```

## Usage

```bash
# Basic analysis
apk-re analyze sample.apk

# Full analysis + HTML report
apk-re analyze sample.apk --report html --output report.html

# JSON report
apk-re analyze sample.apk --report json -o result.json

# With decompilation (requires jadx/apktool in PATH)
apk-re analyze sample.apk --decompile --output-dir ./out

# Quick summary only
apk-re info sample.apk
```

## Example Output

```
[+] Analyzing: sample.apk
[+] Package     : com.example.app
[+] Version     : 1.2.3 (code 123)
[+] Min SDK     : 21
[+] Target SDK  : 34
[+] Permissions : 18 (5 dangerous)
[+] Exported    : 3 activities, 1 service
[+] Secrets     : 2 potential findings
[+] Report saved: report.html
```

## Project Structure

```
android-re-toolkit/
├── src/apk_re/
│   ├── cli.py          # Command line interface
│   ├── analyzer.py     # Core analysis engine
│   ├── decompiler.py   # jadx / apktool wrappers
│   ├── report.py       # HTML & JSON report generators
│   └── utils.py        # Helpers
├── tests/
├── examples/
├── Dockerfile
├── pyproject.toml
└── .github/workflows/ci.yml
```

## Disclaimer

This tool is intended **only for legitimate security research, malware analysis, and educational purposes** on applications you own or have explicit permission to analyze.  

Do **not** use it for piracy, unauthorized access, or any illegal activity.

## License

MIT License – see [LICENSE](LICENSE)

## Author

Built for security research by **Sayan**  
GitHub: [sayan9168](https://github.com/sayan9168)
