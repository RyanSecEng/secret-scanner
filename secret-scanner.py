"""
secret-scanner-v2.py — walks a folder and flags potential secrets.

Two detection modes:
  - FILENAME : the file shouldn't exist here at all (.env, id_rsa, .pem)
  - CONTENT  : a secret is hiding inside a file (passwords, API keys)

Exits 0 if clean, 1 if any findings are found (safe for CI pipelines).

Usage:
  python secret-scanner-v2.py <folder>
  python secret-scanner-v2.py <folder> --json
  python secret-scanner-v2.py --help
"""
import argparse
import json
import os
import re
import sys

MAX_FILE_BYTES = 5 * 1024 * 1024  # skip files larger than 5 MB

SEVERITY_ORDER = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}

SKIP_DIRS = frozenset({
    '.git', 'node_modules', '__pycache__', '.venv', 'venv',
    '.tox', 'dist', 'build', '.mypy_cache', '.pytest_cache',
})

# (substring to match in filename, severity, why)
SENSITIVE_NAMES = [
    ('.env',        'MEDIUM', 'env file may contain secrets'),
    ('id_rsa',      'HIGH',   'private SSH key'),
    ('.pem',        'HIGH',   'private key / certificate'),
    ('.key',        'HIGH',   'private key file'),
    ('credentials', 'MEDIUM', 'credentials file'),
    ('secrets',     'MEDIUM', 'secrets file'),
]

# Negative lookahead: reject obvious placeholder/dummy values at the value position
_DUMMY = (
    r'(?!(?:none|null|false|true|changeme|example|placeholder'
    r'|your[_\-]?(?:key|secret|token)|insert|todo|xxxx|dummy|sample|test))'
)

# (regex, label, severity)
SECRET_PATTERNS = [
    (r'(?i)password\s*=\s*["\']?'  + _DUMMY + r'\S{8,}', 'password',       'HIGH'),
    (r'(?i)api[_-]?key\s*=\s*["\']?' + _DUMMY + r'\S{8,}', 'api_key',      'HIGH'),
    (r'(?i)secret\s*=\s*["\']?'    + _DUMMY + r'\S{8,}', 'secret',         'HIGH'),
    (r'(?i)token\s*=\s*["\']?'     + _DUMMY + r'\S{8,}', 'token',          'MEDIUM'),
    (r'AKIA[0-9A-Z]{16}',                                  'aws_access_key', 'HIGH'),
    (r'sk-[A-Za-z0-9]{20,}',                               'llm_api_key',    'HIGH'),
]


def mask_secret(value):
    """Expose first 4 and last 4 chars; hide the middle to avoid logging real credentials."""
    if len(value) <= 8:
        return '***'
    return f"{value[:4]}***{value[-4:]}"


def read_text(path):
    """Read a file as text with BOM-aware UTF-16 detection; report and skip on any error."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        print(f"[SKIP] {path}: {exc}", file=sys.stderr)
        return None

    if size > MAX_FILE_BYTES:
        mb = size // (1024 * 1024)
        print(f"[SKIP] {path}: file too large ({mb} MB > {MAX_FILE_BYTES // (1024 * 1024)} MB limit)", file=sys.stderr)
        return None

    try:
        with open(path, 'rb') as fh:
            raw = fh.read()
    except OSError as exc:
        print(f"[SKIP] {path}: {exc}", file=sys.stderr)
        return None

    encoding = 'utf-16' if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8'
    return raw.decode(encoding, errors='ignore')


def scan(folder):
    findings = []
    for root, dirs, files in os.walk(folder):
        # Prune noisy/irrelevant dirs in-place so os.walk never descends into them
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for f in files:
            path = os.path.join(root, f)

            # --- FILENAME mode ---
            for name, severity, why in SENSITIVE_NAMES:
                if name in f.lower():
                    findings.append({
                        'severity': severity,
                        'mode':     'FILENAME',
                        'path':     path,
                        'line':     None,
                        'detail':   why,
                    })
                    break  # one finding per file; avoids duplicate hits on e.g. .env.key

            # --- CONTENT mode ---
            content = read_text(path)
            if content is None:
                continue

            for pattern, label, severity in SECRET_PATTERNS:
                for match in re.finditer(pattern, content):
                    line_num = content.count('\n', 0, match.start()) + 1
                    findings.append({
                        'severity': severity,
                        'mode':     'CONTENT',
                        'path':     path,
                        'line':     line_num,
                        'detail':   f"{label}: {mask_secret(match.group(0))}",
                    })

    return findings


def print_human(results):
    if not results:
        print("[+] Clean — no secrets found.")
        return

    sorted_results = sorted(results, key=lambda r: SEVERITY_ORDER.get(r['severity'], 9))

    high = sum(1 for r in results if r['severity'] == 'HIGH')
    med  = sum(1 for r in results if r['severity'] == 'MEDIUM')

    print(f"[!] {len(results)} findings  ({high} HIGH, {med} MEDIUM):\n")
    for r in sorted_results:
        loc = f"{r['path']}:{r['line']}" if r['line'] else r['path']
        print(f"  [{r['severity']}] [{r['mode']}] {loc} — {r['detail']}")


def print_json(results, folder):
    high = sum(1 for r in results if r['severity'] == 'HIGH')
    med  = sum(1 for r in results if r['severity'] == 'MEDIUM')
    print(json.dumps({
        'target':   folder,
        'total':    len(results),
        'high':     high,
        'medium':   med,
        'findings': results,
    }, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description='Scan a directory for exposed secrets '
                    '(API keys, passwords, private keys).'
    )
    parser.add_argument('folder', help='directory to scan (e.g. ./my-project)')
    parser.add_argument('--json', action='store_true',
                        help='output findings as JSON instead of human-readable text')
    args = parser.parse_args()

    if not os.path.isdir(args.folder):
        print(f"[ERROR] Not a folder: {args.folder}", file=sys.stderr)
        print("Fail loud, never fail silent.", file=sys.stderr)
        sys.exit(1)

    if not args.json:
        print(f"Scanning {args.folder}...\n")

    results = scan(args.folder)

    if args.json:
        print_json(results, args.folder)
    else:
        print_human(results)

    sys.exit(1 if results else 0)


if __name__ == '__main__':
    main()
