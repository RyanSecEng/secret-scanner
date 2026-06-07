# Secret Scanner

A lightweight Python tool that scans directories for exposed secrets, API keys, passwords, and private keys. Uses both filename and content detection, with severity scoring.

Built with no external dependencies (Python standard library only), so it runs on any machine with Python installed.

## Why

Secrets accidentally committed to repos or left lying in config files are one of the most common causes of real-world breaches. This tool does a fast first-pass sweep of a directory and flags the things that shouldn't be there.

## Features

- **Two detection modes**, the same split real scanners use:
  - **Filename detection** — flags files that shouldn't exist in the first place (`.env`, `id_rsa`, `*.pem`, `*.key`, `credentials`, `secrets`).
  - **Content detection** — flags secrets *inside* files (passwords, API keys, AWS access keys, LLM API keys) via regex patterns, matching both `=` and `:` assignments so `.env`, JSON, and YAML config are all covered.
- **Secret masking** — matched values are shown as `first4***last4` (e.g. `sk-f***7890`) so real credentials are never echoed to the terminal or CI logs.
- **Line numbers** — content findings include the exact line number (`file.py:42`) for fast triage.
- **CI-friendly exit codes** — exits `1` when findings exist *or* when any file could not be read, `0` only when the scan was clean and complete, so unreadable files never masquerade as "clean".
- **Directory pruning** — automatically skips `.git`, `node_modules`, `__pycache__`, `venv`, `.venv`, `dist`, `build`, and other noisy directories so scans stay fast.
- **File-size guard** — files larger than 5 MB are skipped with a `[SKIP]` notice, preventing hangs on large binaries or data files.
- **Binary-aware** — files whose decoded contents contain NUL bytes are treated as binary and skipped for content scanning, cutting noise from images and compiled artifacts.
- **Improved false-positive filtering** — placeholder and dummy values (`none`, `changeme`, `example`, `your_key`, `xxxx`, etc.) are filtered out by regex lookahead before a finding is raised.
- **Severity scoring** — findings are tagged `HIGH` or `MEDIUM` and sorted with the most serious first.
- **Colored output** — an ASCII banner and color-coded severities (HIGH red, MEDIUM yellow, LOW blue) when writing to a terminal. Color auto-disables when piped/redirected, and respects the `NO_COLOR` environment variable.
- **Escape-injection safe** — untrusted text (file paths and masked values) is sanitized before printing, so a malicious filename or secret carrying ANSI/terminal control codes can't spoof, hide, or rewrite the scanner's output.
- **JSON output** — pass `--json` to emit structured JSON for piping into other tools or dashboards (no banner or color, so output stays machine-parseable).
- **Encoding tolerant** — handles UTF-8 (with or without BOM), UTF-16, and UTF-32 files — including BOM-less UTF-16 written by PowerShell (detected heuristically) — so secrets aren't missed due to encoding quirks.
- **Zero dependencies** — uses only Python standard library (argparse, json, os, re, sys; `ctypes` only on Windows to enable terminal colors).

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

  [HIGH]   [CONTENT]  scan-test/.env:3 — password: DB_P***nter2
  [HIGH]   [CONTENT]  scan-test/.env:4 — llm_api_key: sk-f***7890
  [MEDIUM] [FILENAME] scan-test/.env — env file may contain secrets
```

If nothing is found:

```
[+] Clean — no secrets found.
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

## Recent improvements

- Content patterns match both `=` and `:`, covering JSON/YAML/`.env` config — not just `=`.
- `sk-` LLM key pattern now matches project/service keys (`sk-proj-…`, `sk-svcacct-…`).
- Filename matching is segment-aware, eliminating false positives like `readme.environment` or `notes.keynote`.
- Unreadable files (permissions/I/O) are surfaced and force a non-zero exit instead of being silently skipped.
- Encoding detection extended to UTF-32, UTF-8 BOM, and BOM-less UTF-16; binary content is detected and skipped.
- JSON output gained `low` and `unreadable` counts.
- Terminal control/escape characters in untrusted paths and masked values are now sanitized before display, closing a terminal-injection vector introduced with colored output (JSON output was already safe via `json.dumps` escaping).

## Known Limitations

- **False positives:** regex matching will flag any line resembling a secret (e.g. `password=` or `password:` in documentation or example code). Placeholder filtering reduces noise, but treat findings as leads to verify, not confirmed secrets.
- **Pattern coverage:** detects common secret formats; it is not exhaustive.
- **BOM-less UTF-16 is heuristic:** detection relies on NUL-byte density, so unusual files may still decode imperfectly.

## Roadmap

- Entropy-based detection to further reduce false positives
- Pre-commit hook integration
- Expanded pattern set (GitHub `ghp_`, Slack `xox…`, Google `AIza…`, Stripe, JWTs)
- Baseline / allowlist file to suppress known-accepted findings (fail only on *new* secrets)
- De-duplicate overlapping matches on the same span (one secret, one finding)
- User-supplied custom patterns via a config file
- SARIF output for GitHub code-scanning and other CI dashboards
- Parallel file scanning for large trees

## UX Roadmap

Usability improvements aimed at making everyday and CI use friendlier:

- **Relative, normalized paths** — print paths relative to the scanned folder with consistent separators for readable output.
- **`--quiet` / `-q`** — findings only, suppressing the banner and `[SKIP]` notices for clean CI logs.
- **`--verbose` / `-v`** — show every file scanned/skipped to debug missed detections.
- **Scan a single file** — accept a file path, not just a directory.
- **`--severity <level>`** — only report at or above a threshold (e.g. fail CI on HIGH only).
- **`--exclude <glob>`** — skip extra paths beyond the built-in pruned directories (repeatable).
- **`--max-size <size>`** — make the 5 MB file-size guard tunable.
- **`--version`** and richer `--help` — version flag plus copy-paste examples in the help epilog.
- **`--no-color` / `--force-color` flags** — explicit overrides to complement the automatic TTY detection and `NO_COLOR` support.
- **Scan summary** — a trailing recap line (files scanned, findings, unreadable) and a short exit-code hint.

## License

MIT — see [LICENSE](LICENSE) for details.
