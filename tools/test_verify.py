import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from verify import verify


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'nested').mkdir()
        (self.root / '.nojekyll').write_bytes(b'')
        (self.root / 'nested/worker.js').write_bytes(b'original worker')
        self.expected = [{'path': '.nojekyll', 'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}, {'path': 'nested/worker.js', 'bytes': 15, 'sha256': hashlib.sha256(b'original worker').hexdigest()}]

    def test_exact_hidden_and_nested_inventory(self):
        self.assertEqual(verify(self.root, self.expected), {'status': 'PASS', 'files': 2, 'bytes': 15})

    def test_missing_extra_changed_and_wrong_expected_files(self):
        for kind in ['missing', 'extra', 'changed', 'unsafe']:
            with self.subTest(kind=kind):
                if kind == 'missing': (self.root / '.nojekyll').unlink()
                if kind == 'extra': (self.root / 'extra').write_bytes(b'x')
                if kind == 'changed': (self.root / 'nested/worker.js').write_bytes(b'changed')
                expected = self.expected if kind != 'unsafe' else [{'path': '../escape', 'bytes': 0, 'sha256': '0' * 64}]
                with self.assertRaises(ValueError): verify(self.root, expected)
                (self.root / '.nojekyll').write_bytes(b'')
                (self.root / 'extra').unlink(missing_ok=True)
                (self.root / 'nested/worker.js').write_bytes(b'original worker')

    def test_symbolic_and_hard_links_fail(self):
        link = self.root / 'linked'
        for hard in [False, True]:
            if hard: os.link(self.root / 'nested/worker.js', link)
            else: link.symlink_to(self.root / 'nested/worker.js')
            with self.assertRaises(ValueError): verify(self.root, self.expected)
            link.unlink()

    def test_directory_symlink_fails(self):
        (self.root / 'redirect').symlink_to(self.root / 'nested', target_is_directory=True)
        with self.assertRaises(ValueError): verify(self.root, self.expected)


if __name__ == '__main__':
    unittest.main()
