# Secret Scanner

A lightweight Python tool that scans directories for exposed secrets, API keys, passwords, and private keys. Uses both filename and content detection, with severity scoring.

Built with no external dependencies (Python standard library only), so it runs on any machine with Python installed.

## Why

Secrets accidentally committed to repos or left lying in config files are one of the most common causes of real-world breaches. This tool does a fast first-pass sweep of a directory and flags the things that shouldn't be there.

## Features

- **Two detection modes**, the same split real scanners use:
  - **Filename detection**: flags files that shouldn't exist in the first place (`.env`, `id_rsa`, `*.pem`, `*.key`, `credentials`, `secrets`).
  - **Content detection**: flags secrets *inside* files (passwords, API keys, AWS access keys, LLM API keys) via regex patterns, matching both `=` and `:` assignments so `.env`, JSON, and YAML config are all covered.
- **Secret masking**: matched values are shown as `first4***last4` (e.g. `sk-f***7890`) so real credentials are never echoed to the terminal or CI logs.
- **Line numbers**: content findings include the exact line number (`file.py:42`) for fast triage.
- **CI-friendly exit codes**: exits `1` when findings exist *or* when any file could not be read, `0` only when the scan was clean and complete, so unreadable files never masquerade as "clean".
- **Directory pruning**: automatically skips `.git`, `node_modules`, `__pycache__`, `venv`, `.venv`, `dist`, `build`, and other noisy directories so scans stay fast.
- **File-size guard**: files larger than 5 MB are skipped with a `[SKIP]` notice, preventing hangs on large binaries or data files.
- **Long-line guard**: individual lines over 100 KB (minified bundles, crafted no-newline blobs) are skipped for content matching and reported with a `[SKIP]` notice, so regex work stays bounded and a skipped line never reads as "clean".
- **Binary-aware**: files whose decoded contents contain NUL bytes are treated as binary and skipped for content scanning, cutting noise from images and compiled artifacts.
- **Symlink & special-file safe**: only regular files are read. Symlinks are not followed (so a scan can't be lured outside the target directory) and special files like FIFOs, devices, and sockets are skipped (so a `read()` can't block the scan forever).
- **Improved false-positive filtering**: placeholder and dummy values (`none`, `changeme`, `example`, `your_key`, `xxxx`, etc.) are filtered out by regex lookahead before a finding is raised.
- **Severity scoring**: findings are tagged `HIGH` or `MEDIUM` and sorted with the most serious first.
- **Colored output**: an ASCII banner and color-coded severities (HIGH red, MEDIUM yellow, LOW blue) when writing to a terminal. Color auto-disables when piped/redirected, and respects the `NO_COLOR` environment variable.
- **Escape-injection safe**: untrusted text (file paths and masked values) is sanitized before printing, so a malicious filename or secret can't spoof, hide, or rewrite the scanner's output. This covers ANSI/terminal control codes *and* Unicode bidirectional and zero-width characters ("Trojan Source"-style attacks) that could otherwise visually reorder or conceal text.
- **JSON output**: pass `--json` to emit structured JSON for piping into other tools or dashboards (no banner or color, so output stays machine-parseable).
- **Encoding tolerant**: handles UTF-8 (with or without BOM), UTF-16, and UTF-32 files, including BOM-less UTF-16 written by PowerShell (detected heuristically), so secrets aren't missed due to encoding quirks.
- **Zero dependencies**: uses only Python standard library (argparse, json, os, re, sys; `ctypes` only on Windows to enable terminal colors).

## Requirements

- Python 3.x

## Installation

Clone the repository:

```bash
git clone https://github.com/RyanSecEng/secret-scanner.git
cd secret-scanner
```

Or download the ZIP from the green **Code** button on GitHub and unzip it.

## Usage

```bash
python secret-scanner.py <folder>
python secret-scanner.py <folder> --json
python secret-scanner.py --help
```

Examples:

```bash
# Scan a specific folder
python secret-scanner.py ./my-project

# Scan the current directory
python secret-scanner.py .

# JSON output (useful for CI or piping into other tools)
python secret-scanner.py ./my-project --json
```

> Note: the folder path is relative to where your terminal is currently located. When in doubt, pass a full path.

## Example Output

```
Scanning scan-test...

[!] 3 findings  (2 HIGH, 1 MEDIUM):

  [HIGH]   [CONTENT]  scan-test/.env:3 - password: DB_P***nter2
  [HIGH]   [CONTENT]  scan-test/.env:4 - llm_api_key: sk-f***7890
  [MEDIUM] [FILENAME] scan-test/.env - env file may contain secrets
```

If nothing is found:

```
[+] Clean - no secrets found.
```

With `--json`:

```json
{
  "target": "scan-test",
  "total": 3,
  "high": 2,
  "medium": 1,
  "low": 0,
  "unreadable": 0,
  "findings": [
    {
      "severity": "HIGH",
      "mode": "CONTENT",
      "path": "scan-test/.env",
      "line": 3,
      "detail": "password: DB_P***nter2"
    }
  ]
}
```

## How It Works

The tool walks the target directory recursively with `os.walk()`, pruning noisy directories (`.git`, `node_modules`, etc.) before descending. For each file it (1) checks the file size and skips anything over 5 MB, (2) checks the filename against a list of sensitive extensions (matched on dot-separated name segments, so `secret.pem` hits but `readme.environment` doesn't) and substrings, and (3) detects the encoding, skips binary content, and matches the text against regex patterns for common secret formats. Matched values are masked before display. Findings are collected, tagged with a severity, sorted, and printed with a summary count. Files that genuinely can't be read (permissions, I/O errors) are reported on stderr and force a non-zero exit so an incomplete scan never looks clean.

## Testing

The repo ships with a small test suite covering detection, false-positive
filtering, secret masking, and control-character sanitization. The tests build
throwaway directories with `tempfile` and make no network calls.

```bash
python -m unittest test_secret_scanner -v
```

## What's New in v2

| Feature | Detail |
|---|---|
| Secret masking | Matched values shown as `first4***last4`; originals never logged |
| Line numbers | Content findings include exact line (`path/file.py:42`) |
| CI exit codes | Exits `1` on findings, `0` when clean |
| Directory pruning | Skips `.git`, `node_modules`, `__pycache__`, `venv`, and more |
| File-size guard | Files > 5 MB are skipped with a `[SKIP]` warning |
| False-positive filtering | Regex lookahead rejects placeholder/dummy values |
| argparse CLI | `--help` flag and `--json` output mode |

## Known Limitations

- **False positives:** regex matching will flag any line resembling a secret (e.g. `password=` or `password:` in documentation or example code). Placeholder filtering reduces noise, but treat findings as leads to verify, not confirmed secrets.
- **Pattern coverage:** detects common secret formats; it is not exhaustive.
- **BOM-less UTF-16 is heuristic:** detection relies on NUL-byte density, so unusual files may still decode imperfectly.

## License

MIT. See [LICENSE](LICENSE) for details.
