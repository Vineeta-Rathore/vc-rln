"""Offline regressions for unknown OP operator fees in saved observations."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

import fees


class OperatorFeeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = (Path(__file__).resolve().parents[1] / "data/mainnet_fees.jsonl").read_text(encoding="utf-8")
        cls.observation = next(r for r in map(json.loads, raw.splitlines())
                               if not any(r[n].get("error") for n in ("op", "arb", "eth"))
                               and len(r["op"].get("tx", [])) == 5
                               and all(t.get("operatorFeeWei") is not None for t in r["op"]["tx"]))

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="vc-rln-fee-test-")
        self.original_data = fees.DATA
        fees.DATA = Path(self.directory.name)
        self.row = copy.deepcopy(self.observation)
        self.row["ts"] = fees.FEE_FROM

    def tearDown(self):
        fees.DATA = self.original_data
        self.directory.cleanup()

    def select(self):
        (fees.DATA / "mainnet_fees.jsonl").write_text(json.dumps(self.row) + "\n", encoding="utf-8")
        return fees.samples()

    def test_explicit_zero_is_a_known_component(self):
        self.row["op"]["tx"][0]["operatorFeeWei"] = "0"
        self.assertEqual(len(self.select()), 1)

    def test_unavailable_component_cannot_become_zero(self):
        self.row["op"]["tx"][0]["operatorFeeWei"] = None
        with self.assertRaisesRegex(ValueError, "Unknown OP operator fee"):
            self.select()

    def test_missing_component_cannot_become_zero(self):
        del self.row["op"]["tx"][0]["operatorFeeWei"]
        with self.assertRaisesRegex(ValueError, "Unknown OP operator fee"):
            self.select()

    def test_historical_chain_errors_remain_excluded(self):
        self.row["op"]["error"] = "recorded test read failure"
        self.row["op"]["tx"][0]["operatorFeeWei"] = None
        self.assertEqual(self.select(), [])


if __name__ == "__main__":
    unittest.main()
