"""
Tests for secret-scanner.

Everything runs against throwaway directories built with tempfile, so the suite
touches no real files outside its own temp dir and makes no network calls.

Run with:  python -m unittest test_secret_scanner
"""
import importlib.util
import os
import tempfile
import unittest

# The script's filename has a hyphen, so it can't be imported normally.
_spec = importlib.util.spec_from_file_location(
    "secret_scanner",
    os.path.join(os.path.dirname(__file__), "secret-scanner.py"),
)
scanner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scanner)


def write(folder, name, content="", encoding="utf-8"):
    """Create a file inside `folder` and return its path."""
    path = os.path.join(folder, name)
    with open(path, "w", encoding=encoding) as fh:
        fh.write(content)
    return path


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def details(self, findings):
        return [f["detail"] for f in findings]

    def test_clean_directory_has_no_findings(self):
        write(self.dir, "notes.txt", "nothing interesting here\n")
        findings, errors = scanner.scan(self.dir)
        self.assertEqual(findings, [])
        self.assertEqual(errors, [])

    def test_password_in_content_is_flagged(self):
        write(self.dir, "config.ini", "password = SuperSecret123\n")
        findings, _ = scanner.scan(self.dir)
        self.assertTrue(any(f["mode"] == "CONTENT" for f in findings))
        self.assertTrue(any("password" in d for d in self.details(findings)))

    def test_secret_value_is_masked_not_leaked(self):
        # The whole point of masking: the real value must never appear in output.
        write(self.dir, "app.env", "api_key = abcd1234efgh5678ijkl\n")
        findings, _ = scanner.scan(self.dir)
        joined = " ".join(self.details(findings))
        self.assertNotIn("abcd1234efgh5678ijkl", joined)
        self.assertIn("***", joined)

    def test_aws_access_key_is_detected(self):
        write(self.dir, "creds.txt", "AKIAIOSFODNN7EXAMPLE\n")
        findings, _ = scanner.scan(self.dir)
        self.assertTrue(any("aws_access_key" in d for d in self.details(findings)))

    def test_sensitive_filename_is_flagged(self):
        write(self.dir, "server.pem", "")
        findings, _ = scanner.scan(self.dir)
        self.assertTrue(any(f["mode"] == "FILENAME" for f in findings))

    def test_placeholder_values_are_ignored(self):
        write(self.dir, "sample.env", "password = changeme\napi_key = your_key\n")
        findings, _ = scanner.scan(self.dir)
        self.assertEqual([f for f in findings if f["mode"] == "CONTENT"], [])

    def test_lookalike_filename_is_not_flagged(self):
        # 'readme.environment' must not trip the 'env' segment rule.
        write(self.dir, "readme.environment", "")
        findings, _ = scanner.scan(self.dir)
        self.assertEqual(findings, [])

    def test_skip_dirs_are_not_descended(self):
        nested = os.path.join(self.dir, "node_modules")
        os.makedirs(nested)
        write(nested, "leaked.env", "password = ShouldBeIgnored99\n")
        findings, _ = scanner.scan(self.dir)
        self.assertEqual(findings, [])

    def test_long_line_is_not_content_scanned(self):
        # One enormous line is skipped, so a secret buried in it isn't reported.
        long_line = "x" * (scanner.MAX_LINE_CHARS + 1) + " password = SuperSecret123"
        write(self.dir, "bundle.min.js", long_line + "\n")
        findings, _ = scanner.scan(self.dir)
        self.assertEqual([f for f in findings if f["mode"] == "CONTENT"], [])

    def test_normal_lines_scanned_even_when_a_long_line_is_present(self):
        # A short secret on its own line is still found despite a long line nearby.
        content = "password = SuperSecret123\n" + "y" * (scanner.MAX_LINE_CHARS + 1) + "\n"
        write(self.dir, "mixed.txt", content)
        findings, _ = scanner.scan(self.dir)
        self.assertTrue(any(f["mode"] == "CONTENT" for f in findings))

    def test_symlink_content_is_not_read(self):
        # A symlink could point outside the scan target; we must not read through
        # it. The real file is still scanned; the link must add no CONTENT finding.
        real = write(self.dir, "real.txt", "password = SuperSecret123\n")
        link = os.path.join(self.dir, "link.txt")
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError, AttributeError):
            self.skipTest("symlinks not supported on this platform/account")
        findings, errors = scanner.scan(self.dir)
        content_paths = [f["path"] for f in findings if f["mode"] == "CONTENT"]
        self.assertIn(real, content_paths)
        self.assertNotIn(link, content_paths)
        # Skipping the symlink is deliberate, not a read error.
        self.assertEqual(errors, [])


class SafetyTests(unittest.TestCase):
    """Untrusted text (filenames, secret values) must be neutralised before display."""

    def test_control_characters_are_escaped(self):
        # A value carrying an ANSI escape must not survive into output verbatim.
        evil = "secret\x1b[2Jvalue"
        self.assertNotIn("\x1b", scanner._sanitize(evil))
        self.assertIn("\\x1b", scanner._sanitize(evil))

    def test_bidi_override_is_escaped(self):
        # Trojan-Source: a right-to-left override can visually reorder output.
        evil = "safe" + chr(0x202e) + "evil"
        out = scanner._sanitize(evil)
        self.assertNotIn(chr(0x202e), out)
        self.assertIn("\\u202e", out)

    def test_zero_width_character_is_escaped(self):
        # Zero-width chars can hide text; they must be made visible.
        out = scanner._sanitize("ab" + chr(0x200b) + "cd")
        self.assertNotIn(chr(0x200b), out)
        self.assertIn("\\u200b", out)

    def test_plain_text_is_left_untouched(self):
        self.assertEqual(scanner._sanitize("hello-world.env:42"), "hello-world.env:42")

    def test_short_value_is_fully_hidden(self):
        self.assertEqual(scanner.mask_secret("short"), "***")

    def test_long_value_keeps_only_edges(self):
        masked = scanner.mask_secret("abcdefghijklmnop")
        self.assertEqual(masked, "abcd***mnop")


if __name__ == "__main__":
    unittest.main(verbosity=2)
