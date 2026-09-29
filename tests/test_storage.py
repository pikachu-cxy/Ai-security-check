import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_runtime.storage import SQLiteStore


class StorageTests(unittest.TestCase):
    def test_default_store_is_independent_of_current_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.dict(os.environ, {"SECURITY_RUNTIME_STATE_DIR": str(root / "state")}):
                with patch.object(Path, "cwd", return_value=root / "one"):
                    first = SQLiteStore()
                with patch.object(Path, "cwd", return_value=root / "two"):
                    second = SQLiteStore()
            self.assertEqual(first.path, second.path)
            self.assertTrue(first.path.is_file())
