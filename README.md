# Secret Scanner

A lightweight Python tool that scans directories for exposed secrets — API keys, passwords, and private keys — using both filename and content detection, with severity scoring.

Built with no external dependencies (Python standard library only), so it runs on any machine with Python installed.

## Why

Secrets accidentally committed to repos or left lying in config files are one of the most common causes of real-world breaches. This tool does a fast first-pass sweep of a directory and flags the things that shouldn't be there.

## Features

- **Two detection modes**, the same split real scanners use:
  - **Filename detection** — flags files that shouldn't exist in the first place (`.env`, `id_rsa`, `*.pem`, `*.key`, `credentials`, `secrets`).
  - **Content detection** — flags secrets *inside* files (passwords, API keys, AWS access keys, LLM API keys) via regex patterns.
- **Severity scoring** — findings are tagged `HIGH` or `MEDIUM` and sorted with the most serious first.
- **Encoding tolerant** — handles UTF-8 and UTF-16 encoded files (e.g. files written by PowerShell), so secrets aren't missed due to encoding quirks.
- **Zero dependencies** — uses only `os`, `re`, and `sys` from the standard library.

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
```

Examples:

```bash
# Scan a specific folder
python secret-scanner.py ./my-project

# Scan the current directory
python secret-scanner.py .
```

> Note: the folder path is relative to where your terminal is currently located. When in doubt, pass a full path.

## Example Output

```
Scanning scan-test...

[!] 3 findings  (2 HIGH, 1 MEDIUM):

  [HIGH]   [CONTENT]  scan-test/.env — password: DB_PASSWORD=hunter2
  [HIGH]   [CONTENT]  scan-test/.env — llm_api_key: sk-fake-test-1234567890
  [MEDIUM] [FILENAME] scan-test/.env — env file may contain secrets
```

If nothing is found:

```
[+] Clean — no secrets found.
```

## How It Works

The tool walks the target directory recursively with `os.walk()`. For each file it (1) checks the filename against a list of sensitive names, and (2) reads the contents and matches them against a set of regex patterns for common secret formats. Findings are collected, tagged with a severity, sorted, and printed with a summary count.

## Known Limitations

- **False positives:** regex matching will flag any line resembling a secret (e.g. `password=` in documentation or example code). Treat findings as leads to verify, not confirmed secrets.
- **Large directories:** the current version reads every file and is best pointed at project folders rather than entire drives.
- **Pattern coverage:** detects common secret formats; it is not exhaustive.

## Roadmap

- Command-line flags via `argparse` (`--help`, ignore lists, output formats)
- JSON output for piping into other tools
- Directory exclusions and file-size limits for scanning larger trees
- Entropy-based detection to reduce false positives
- Pre-commit hook integration

## License

MIT
