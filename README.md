# Secret Scanner

A lightweight Python tool that scans directories for exposed secrets, API keys, passwords, and private keys. Uses both filename and content detection, with severity scoring.

Built with no external dependencies (Python standard library only), so it runs on any machine with Python installed.

## Why

Secrets accidentally committed to repos or left lying in config files are one of the most common causes of real-world breaches. This tool does a fast first-pass sweep of a directory and flags the things that shouldn't be there.

## Features

- **Two detection modes**, the same split real scanners use:
  - **Filename detection** — flags files that shouldn't exist in the first place (`.env`, `id_rsa`, `*.pem`, `*.key`, `credentials`, `secrets`).
  - **Content detection** — flags secrets *inside* files (passwords, API keys, AWS access keys, LLM API keys) via regex patterns.
- **Secret masking** — matched values are shown as `first4***last4` (e.g. `sk-f***7890`) so real credentials are never echoed to the terminal or CI logs.
- **Line numbers** — content findings include the exact line number (`file.py:42`) for fast triage.
- **CI-friendly exit codes** — exits `1` when findings exist, `0` when clean, so it drops straight into a pipeline step.
- **Directory pruning** — automatically skips `.git`, `node_modules`, `__pycache__`, `venv`, `.venv`, `dist`, `build`, and other noisy directories so scans stay fast.
- **File-size guard** — files larger than 5 MB are skipped with a `[SKIP]` notice, preventing hangs on large binaries or data files.
- **Improved false-positive filtering** — placeholder and dummy values (`none`, `changeme`, `example`, `your_key`, `xxxx`, etc.) are filtered out by regex lookahead before a finding is raised.
- **Severity scoring** — findings are tagged `HIGH` or `MEDIUM` and sorted with the most serious first.
- **JSON output** — pass `--json` to emit structured JSON for piping into other tools or dashboards.
- **Encoding tolerant** — handles UTF-8 and UTF-16 encoded files (e.g. files written by PowerShell), so secrets aren't missed due to encoding quirks.
- **Zero dependencies** — uses only Python standard library (argparse, json, os, re, sys).

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

The tool walks the target directory recursively with `os.walk()`, pruning noisy directories (`.git`, `node_modules`, etc.) before descending. For each file it (1) checks the file size and skips anything over 5 MB, (2) checks the filename against a list of sensitive names, and (3) reads the contents and matches them against regex patterns for common secret formats. Matched values are masked before display. Findings are collected, tagged with a severity, sorted, and printed with a summary count.

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

- **False positives:** regex matching will flag any line resembling a secret (e.g. `password=` in documentation or example code). Placeholder filtering reduces noise, but treat findings as leads to verify, not confirmed secrets.
- **Pattern coverage:** detects common secret formats; it is not exhaustive.

## Roadmap

- Entropy-based detection to further reduce false positives
- Pre-commit hook integration

## License

MIT — see [LICENSE](LICENSE) for details.
