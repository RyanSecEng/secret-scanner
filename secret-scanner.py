"""
secret-scanner.py: walks a folder and flags potential secrets.

Two detection modes:
  - FILENAME : the file shouldn't exist here at all (.env, id_rsa, .pem)
  - CONTENT  : a secret is hiding inside a file (passwords, API keys)

Exits 0 if clean, 1 if any findings are found OR any files could not be read
(safe for CI pipelines: unreadable files never masquerade as "clean").

Usage:
  python secret-scanner.py <folder>
  python secret-scanner.py <folder> --json
  python secret-scanner.py --help
"""
import argparse
import errno
import json
import os
import re
import stat
import sys
from collections import Counter

MAX_FILE_BYTES = 5 * 1024 * 1024

# Lines longer than this are skipped for content matching. Real config secrets
# live on short lines; a single enormous line is almost always a minified bundle
# or a crafted no-newline blob, where regex work has poor signal and (as the
# pattern set grows) is where backtracking risk would creep in.
MAX_LINE_CHARS = 100 * 1024

BANNER = r"""
                            .-------.
                           /         \
                          |    ( )    |
                           \         /
                            \       /
                             \     /
                              '---'
   ____                 _     ____
  / ___|  ___  ___ _ __| |_  / ___|  ___ __ _ _ __  _ __   ___ _ __
  \___ \ / _ \/ __| '__| __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
   ___) |  __/ (__| |  | |_   ___) | (_| (_| | | | | | | |  __/ |
  |____/ \___|\___|_|   \__| |____/ \___\__,_|_| |_|_| |_|\___|_|

  secret-scanner v2 - finds exposed secrets before attackers do
"""

# ANSI styling, enabled only when writing to a real terminal (see _init_color).
_RESET = '\033[0m'
_BOLD = '\033[1m'
_CYAN = '\033[36m'
_GREEN = '\033[32m'
_SEVERITY_COLORS = {
    'HIGH':   '\033[1;31m',
    'MEDIUM': '\033[33m',
    'LOW':    '\033[34m',
}

_use_color = False  # decided at runtime in _init_color()

SEVERITY_ORDER = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}

SKIP_DIRS = frozenset({
    '.git', 'node_modules', '__pycache__', '.venv', 'venv',
    '.tox', 'dist', 'build', '.mypy_cache', '.pytest_cache',
})

# Sensitive file *extensions*, matched against dot-separated name segments so
# `secret.pem` / `.env.local` hit but `readme.environment` / `notes.keynote` don't.
# (segment, severity, why)
SENSITIVE_EXT_SEGMENTS = [
    ('env', 'MEDIUM', 'env file may contain secrets'),
    ('pem', 'HIGH',   'private key / certificate'),
    ('key', 'HIGH',   'private key file'),
]

# Sensitive name *substrings*: meaningful anywhere in the filename.
# (substring, severity, why)
SENSITIVE_NAME_SUBSTRINGS = [
    ('id_rsa',      'HIGH',   'private SSH key'),
    ('credentials', 'MEDIUM', 'credentials file'),
    ('secrets',     'MEDIUM', 'secrets file'),
]

# Negative lookahead: reject obvious placeholder/dummy values at the value position.
# NOTE: 'test' is intentionally NOT listed; real secrets often start with "test".
_DUMMY = (
    r'(?!(?:none|null|false|true|changeme|example|placeholder'
    r'|your[_\-]?(?:key|secret|token)|insert|todo|xxxx|dummy|sample))'
)

# Value characters: stop at quotes/whitespace so a trailing closing quote is
# never swallowed into the captured (and masked) secret.
_VAL = r'[^"\'\s]{8,}'

# (regex, label, severity). Accept both `=` and `:` so JSON/YAML/.env all match.
SECRET_PATTERNS = [
    (r'(?i)password\s*[=:]\s*["\']?'  + _DUMMY + _VAL, 'password',       'HIGH'),
    (r'(?i)api[_-]?key\s*[=:]\s*["\']?' + _DUMMY + _VAL, 'api_key',      'HIGH'),
    (r'(?i)secret\s*[=:]\s*["\']?'    + _DUMMY + _VAL, 'secret',         'HIGH'),
    (r'(?i)token\s*[=:]\s*["\']?'     + _DUMMY + _VAL, 'token',          'MEDIUM'),
    (r'AKIA[0-9A-Z]{16}',                              'aws_access_key', 'HIGH'),
    (r'sk-[A-Za-z0-9_-]{20,}',                         'llm_api_key',    'HIGH'),
]


def _enable_windows_vt():
    """Turn on ANSI escape processing in the Windows console; return True on success."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # 0x0004 = ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def _init_color(stream):
    """Enable ANSI color when `stream` is a TTY and color isn't explicitly disabled."""
    global _use_color
    if os.environ.get('NO_COLOR') is not None:
        _use_color = False
        return
    if not (hasattr(stream, 'isatty') and stream.isatty()):
        _use_color = False
        return
    _use_color = _enable_windows_vt() if sys.platform == 'win32' else True


# Filenames and file contents are untrusted, so we strip anything that could
# drive the terminal before printing it: C0/C1/DEL controls (ANSI escapes,
# window-title tricks) and the bidi/zero-width characters behind "Trojan Source"
# attacks. Defined as code points so this file itself stays plain ASCII.
_UNSAFE_RANGES = (
    (0x00, 0x1f), (0x7f, 0x9f),   # C0 controls, DEL, C1 controls
    (0x200b, 0x200f),             # zero-width space/joiners, LRM, RLM
    (0x202a, 0x202e),             # bidi embeddings / overrides
    (0x2066, 0x2069),             # bidi isolates
    (0x061c, 0x061c),             # Arabic letter mark
    (0xfeff, 0xfeff),             # zero-width no-break space (BOM)
)
_UNSAFE_RE = re.compile(
    '[' + ''.join(f'{chr(lo)}-{chr(hi)}' for lo, hi in _UNSAFE_RANGES) + ']'
)


def _sanitize(text):
    """Escape terminal-control and text-spoofing characters in untrusted text."""
    def _escape(match):
        cp = ord(match.group())
        return f'\\x{cp:02x}' if cp <= 0xff else f'\\u{cp:04x}'
    return _UNSAFE_RE.sub(_escape, str(text))


def color(text, code):
    """Wrap `text` in an ANSI color code when color is active; otherwise return it plain."""
    if not _use_color or not code:
        return text
    return f"{code}{text}{_RESET}"


def mask_secret(value):
    """Expose first 4 and last 4 chars; hide the middle to avoid logging real credentials."""
    if len(value) <= 8:
        return '***'
    return f"{value[:4]}***{value[-4:]}"


def _detect_encoding(raw):
    """Best-effort text encoding from BOM, falling back to a BOM-less UTF-16 heuristic."""
    # UTF-32 BOMs must be checked before UTF-16 (utf-32-le starts with the utf-16-le BOM).
    if raw.startswith((b'\xff\xfe\x00\x00', b'\x00\x00\xfe\xff')):
        return 'utf-32'
    if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        return 'utf-16'
    if raw.startswith(b'\xef\xbb\xbf'):
        return 'utf-8-sig'

    # BOM-less UTF-16: lots of interleaved NUL bytes. Position of the NULs
    # (even vs odd offsets) tells big- from little-endian.
    sample = raw[:4096]
    if sample and sample.count(0) > len(sample) * 0.30:
        even_nulls = sample[0::2].count(0)
        odd_nulls = sample[1::2].count(0)
        return 'utf-16-be' if even_nulls > odd_nulls else 'utf-16-le'

    return 'utf-8'


# O_NOFOLLOW makes open() refuse a final-component symlink (raising ELOOP) rather
# than silently following it. Not defined on Windows, where it falls back to 0 and
# symlink creation already needs privilege.
_O_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)


def _nofollow_opener(path, flags):
    return os.open(path, flags | _O_NOFOLLOW)


def read_text(path, errors):
    """Read a file as text with encoding detection.

    Returns the decoded text, or None when the file is skipped. Genuine read
    failures (permissions, I/O) are appended to `errors` so the caller can fail
    loud; deliberate skips (too large, binary) are not treated as errors.
    """
    # `path` is attacker-influenced (filenames), so sanitize before it hits stderr.
    safe_path = _sanitize(path)
    try:
        st = os.lstat(path)  # lstat, so we inspect the link itself, not its target
    except OSError as exc:
        print(f"[SKIP] {safe_path}: {_sanitize(exc)}", file=sys.stderr)
        errors.append((path, str(exc)))
        return None

    # Only read plain files. Symlinks could lead outside the scan target, and
    # special files (FIFOs, devices, sockets) can hang read() forever - skip both.
    # Deliberate skips like these aren't errors, so we don't record them.
    if not stat.S_ISREG(st.st_mode):
        return None

    size = st.st_size
    if size > MAX_FILE_BYTES:
        mb = size // (1024 * 1024)
        print(f"[SKIP] {safe_path}: file too large ({mb} MB > {MAX_FILE_BYTES // (1024 * 1024)} MB limit)",
              file=sys.stderr)
        return None

    try:
        # Open without following a symlink, closing the gap between the lstat
        # above and here: if the path is swapped for a symlink in between, the
        # open fails instead of leading us out of the scan tree.
        with open(path, 'rb', opener=_nofollow_opener) as fh:
            raw = fh.read()
    except OSError as exc:
        # ELOOP means O_NOFOLLOW caught a symlink that appeared after the check;
        # that's a deliberate skip, not a read failure to report.
        if getattr(exc, 'errno', None) == errno.ELOOP:
            return None
        print(f"[SKIP] {safe_path}: {_sanitize(exc)}", file=sys.stderr)
        errors.append((path, str(exc)))
        return None

    text = raw.decode(_detect_encoding(raw), errors='ignore')

    # A NUL surviving decode means this isn't really text, so skip binary content.
    if '\x00' in text:
        return None

    return text


def _filename_finding(filename, path):
    """Return a single FILENAME finding for a suspicious name, or None."""
    lower = filename.lower()

    # Dot-separated segments: '.env.local' -> {'env', 'local'}, 'id_rsa.pem' -> {'id_rsa', 'pem'}
    segments = set(lower.lstrip('.').split('.'))
    for seg, severity, why in SENSITIVE_EXT_SEGMENTS:
        if seg in segments:
            return {'severity': severity, 'mode': 'FILENAME', 'path': path, 'line': None, 'detail': why}

    for sub, severity, why in SENSITIVE_NAME_SUBSTRINGS:
        if sub in lower:
            return {'severity': severity, 'mode': 'FILENAME', 'path': path, 'line': None, 'detail': why}

    return None


def scan(folder):
    findings = []
    errors = []
    for root, dirs, files in os.walk(folder):
        # Prune noisy/irrelevant dirs in-place so os.walk never descends into them
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for f in files:
            path = os.path.join(root, f)

            name_finding = _filename_finding(f, path)
            if name_finding is not None:
                findings.append(name_finding)

            content = read_text(path, errors)
            if content is None:
                continue

            skipped_lines = 0
            for line_num, line in enumerate(content.split('\n'), 1):
                if len(line) > MAX_LINE_CHARS:
                    skipped_lines += 1
                    continue
                for pattern, label, severity in SECRET_PATTERNS:
                    for match in re.finditer(pattern, line):
                        findings.append({
                            'severity': severity,
                            'mode':     'CONTENT',
                            'path':     path,
                            'line':     line_num,
                            'detail':   f"{label}: {mask_secret(match.group(0))}",
                        })

            # Be loud about skipped lines so a long line never masquerades as clean.
            if skipped_lines:
                print(f"[SKIP] {_sanitize(path)}: {skipped_lines} line(s) over "
                      f"{MAX_LINE_CHARS // 1024} KB not content-scanned", file=sys.stderr)

    return findings, errors


def _severity_breakdown(results):
    """Return a 'N HIGH, M MEDIUM' style string covering every severity present."""
    counts = Counter(r['severity'] for r in results)
    ordered = sorted(counts, key=lambda s: SEVERITY_ORDER.get(s, 9))
    return ', '.join(f"{counts[s]} {s}" for s in ordered)


def print_human(results, errors):
    if not results:
        print(color("[+] Clean - no secrets found.", _GREEN))
    else:
        sorted_results = sorted(results, key=lambda r: SEVERITY_ORDER.get(r['severity'], 9))
        print(color(f"[!] {len(results)} findings", _BOLD) + f"  ({_severity_breakdown(results)}):\n")
        for r in sorted_results:
            loc = f"{r['path']}:{r['line']}" if r['line'] else r['path']
            tag = color(f"[{r['severity']}]", _SEVERITY_COLORS.get(r['severity'], ''))
            # path and detail (masked secret) are untrusted, so sanitize before printing.
            print(f"  {tag} [{r['mode']}] {_sanitize(loc)} - {_sanitize(r['detail'])}")

    if errors:
        print(f"\n[!] {len(errors)} file(s) could not be read and were NOT scanned "
              f"(see stderr above). Treat results as incomplete.", file=sys.stderr)


def print_json(results, folder, errors):
    counts = Counter(r['severity'] for r in results)
    print(json.dumps({
        'target':     folder,
        'total':      len(results),
        'high':       counts.get('HIGH', 0),
        'medium':     counts.get('MEDIUM', 0),
        'low':        counts.get('LOW', 0),
        'unreadable': len(errors),
        'findings':   results,
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
        print(f"[ERROR] Not a folder: {_sanitize(args.folder)}", file=sys.stderr)
        sys.exit(1)

    if not args.json:
        _init_color(sys.stdout)
        print(color(BANNER, _CYAN))
        print(f"Scanning {_sanitize(args.folder)}...\n")

    results, errors = scan(args.folder)

    if args.json:
        print_json(results, args.folder, errors)
    else:
        print_human(results, errors)

    # Non-zero if we found secrets OR couldn't read something (don't fake "clean").
    sys.exit(1 if results or errors else 0)


if __name__ == '__main__':
    main()
