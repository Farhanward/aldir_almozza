from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aldir_almozza.batch import evaluate
from aldir_almozza.datasets import convert_nvd
from aldir_almozza.signals import aggregate


class AlDirTests(unittest.TestCase):
    def test_aggregate_blocks_high_signal(self):
        result = aggregate([{"kind": "cve", "value": "CVE-1", "severity": "HIGH", "source": "a"}])
        self.assertEqual(len(result["blocklist"]), 1)

    def test_convert_and_batch_fixture(self):
        with tempfile.TemporaryDirectory(dir="C:/Projects") as tmp:
            src = Path(tmp) / "nvd.jsonl"
            out = Path(tmp) / "signals.jsonl"
            src.write_text('{"id":"CVE-1","severity":"HIGH"}\n{"id":"CVE-2","severity":"LOW"}\n', encoding="utf-8")
            convert_nvd(src, out)
            summary = evaluate(out)
            self.assertEqual(summary["errors"], 0)


if __name__ == "__main__":
    unittest.main()

