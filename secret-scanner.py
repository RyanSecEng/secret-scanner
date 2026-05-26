"""
secret-scanner.py — walks a folder and flags potential secrets.

Two detection modes (like real scanners):
  - FILENAME : the file shouldn't exist here at all (.env, id_rsa, .pem)
  - CONTENT  : a secret is hiding inside a file (passwords, API keys)

Usage:
  python secret-scanner.py <folder>
  python secret-scanner.py <folder> --json
  python secret-scanner.py --help
"""
import argparse
import json
import os
import re
import sys

# (substring to match in filename, severity, why)
SENSITIVE_NAMES = [
    ('.env', 'MEDIUM', 'env file may contain secrets'),
    ('id_rsa', 'HIGH', 'private SSH key'),
    ('.pem', 'HIGH', 'private key / certificate'),
    ('.key', 'HIGH', 'private key file'),
    ('credentials', 'MEDIUM', 'credentials file'),
    ('secrets', 'MEDIUM', 'secrets file'),
]

# (regex, label, severity)
SECRET_PATTERNS = [
    (r'(?i)password\s*=\s*["\']?\S+', 'password', 'HIGH'),
    (r'(?i)api[_-]?key\s*=\s*["\']?\S+', 'api_key', 'HIGH'),
    (r'(?i)secret\s*=\s*["\']?\S+', 'secret', 'HIGH'),
    (r'(?i)token\s*=\s*["\']?\S+', 'token', 'MEDIUM'),
    (r'AKIA[0-9A-Z]{16}', 'aws_access_key', 'HIGH'),
    (r'sk-[A-Za-z0-9]{20,}', 'llm_api_key', 'HIGH'),
]


def read_text(path):
    """Read a file as text, tolerating UTF-8 and UTF-16 (PowerShell echo)."""
    try:
        with open(path, 'rb') as fh:
            raw = fh.read()
    except Exception:
        return None
    # strip null bytes so UTF-16 ASCII content decodes cleanly
    return raw.replace(b'\x00', b'').decode('utf-8', errors='ignore')


def scan(folder):
    findings = []
    for root, _, files in os.walk(folder):
        for f in files:
            path = os.path.join(root, f)

            # --- FILENAME mode ---
            for name, severity, why in SENSITIVE_NAMES:
                if name in f.lower():
                    findings.append({
                        'severity': severity,
                        'mode': 'FILENAME',
                        'path': path,
                        'detail': why,
                    })

            # --- CONTENT mode ---
            content = read_text(path)
            if content is None:
                continue
            for pattern, label, severity in SECRET_PATTERNS:
                for match in re.findall(pattern, content):
                    findings.append({
                        'severity': severity,
                        'mode': 'CONTENT',
                        'path': path,
                        'detail': f"{label}: {match[:60]}",
                    })
    return findings


def print_human(results):
    if not results:
        print("[+] Clean — no secrets found.")
        return

    order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    results.sort(key=lambda r: order.get(r['severity'], 9))

    high = sum(1 for r in results if r['severity'] == 'HIGH')
    med = sum(1 for r in results if r['severity'] == 'MEDIUM')

    print(f"[!] {len(results)} findings  ({high} HIGH, {med} MEDIUM):\n")
    for r in results:
        print(f"  [{r['severity']}] [{r['mode']}] {r['path']} — {r['detail']}")


def print_json(results, folder):
    high = sum(1 for r in results if r['severity'] == 'HIGH')
    med = sum(1 for r in results if r['severity'] == 'MEDIUM')
    output = {
        'target': folder,
        'total': len(results),
        'high': high,
        'medium': med,
        'findings': results,
    }
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description='Scan a directory for exposed secrets '
                    '(API keys, passwords, private keys).'
    )
    parser.add_argument(
        'folder',
        help='the folder to scan (e.g. ./my-project or a full path)'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='output findings as JSON instead of human-readable text'
    )
    args = parser.parse_args()

    # fail loud if the target doesn't exist, instead of silently scanning nothing
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


if __name__ == '__main__':
    main()
