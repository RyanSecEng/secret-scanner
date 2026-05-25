"""
secret-scanner.py — walks a folder and flags potential secrets.

Two detection modes (just like real scanners):
  - FILENAME rules : the file shouldn't exist here at all (.env, id_rsa, .pem)
  - CONTENT rules  : a secret is hiding inside a file (passwords, API keys)

Usage:  python secret-scanner.py <folder>
"""
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
                    findings.append((severity, 'FILENAME', path, why))

            # --- CONTENT mode ---
            content = read_text(path)
            if content is None:
                continue
            for pattern, label, severity in SECRET_PATTERNS:
                for match in re.findall(pattern, content):
                    findings.append((severity, 'CONTENT', path, f"{label}: {match[:60]}"))
    return findings


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else '.'
    print(f"Scanning {target}...\n")
    results = scan(target)

    if not results:
        print("[+] Clean — no secrets found.")
        return

    # sort HIGH before MEDIUM
    order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    results.sort(key=lambda r: order.get(r[0], 9))

    high = sum(1 for r in results if r[0] == 'HIGH')
    med = sum(1 for r in results if r[0] == 'MEDIUM')

    print(f"[!] {len(results)} findings  ({high} HIGH, {med} MEDIUM):\n")
    for severity, mode, path, detail in results:
        print(f"  [{severity}] [{mode}] {path} — {detail}")


if __name__ == '__main__':
    main()
