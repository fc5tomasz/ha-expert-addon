from __future__ import annotations

import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path


APP_PATH = Path(__file__).resolve().parents[1] / "addon" / "rootfs" / "opt" / "ha_expert" / "app.py"


def load_app():
    if "aiohttp" not in sys.modules:
        aiohttp_stub = types.ModuleType("aiohttp")
        aiohttp_stub.ClientTimeout = object
        aiohttp_stub.ClientSession = object
        web_stub = types.SimpleNamespace(
            Application=object,
            Request=object,
            Response=object,
            json_response=lambda *args, **kwargs: None,
            FileResponse=lambda *args, **kwargs: None,
            get=lambda *args, **kwargs: None,
            post=lambda *args, **kwargs: None,
            static=lambda *args, **kwargs: None,
            run_app=lambda *args, **kwargs: None,
        )
        aiohttp_stub.web = web_stub
        sys.modules["aiohttp"] = aiohttp_stub
        sys.modules["aiohttp.web"] = web_stub
    spec = importlib.util.spec_from_file_location("ha_expert_app_under_test", APP_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {APP_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RuntimeSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = load_app()

    def test_automation_is_normalized_to_start_with_alias(self) -> None:
        item = self.app._single_automation_from_yaml(
            {
                "id": "test_id",
                "mode": "single",
                "alias": "Test automation",
                "action": [{"service": "logbook.log", "data": {"name": "HA Expert", "message": "test"}}],
                "trigger": [{"platform": "state", "entity_id": "input_boolean.test"}],
            }
        )

        self.assertEqual(list(item.keys()), ["alias", "trigger", "action", "mode", "id"])
        dumped = self.app._dump_yaml([item])
        self.assertTrue(dumped.startswith("- alias: Test automation\n"), dumped)

    def test_script_is_normalized_to_keep_alias_first_inside_key(self) -> None:
        key, script = self.app._single_script_from_yaml(
            {
                "test_script": {
                    "mode": "single",
                    "sequence": [{"service": "logbook.log", "data": {"name": "HA Expert", "message": "test"}}],
                    "alias": "Test script",
                }
            }
        )

        self.assertEqual(key, "test_script")
        self.assertEqual(list(script.keys()), ["alias", "sequence", "mode"])
        dumped = self.app._dump_yaml({key: script})
        self.assertTrue(dumped.startswith("test_script:\n  alias: Test script\n"), dumped)

    def test_invalid_automation_without_alias_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "alias"):
            self.app._single_automation_from_yaml(
                {
                    "trigger": [{"platform": "state", "entity_id": "input_boolean.test"}],
                    "action": [{"service": "logbook.log"}],
                }
            )

    def test_append_block_only_changes_file_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "automations.yaml"
            path.write_text("- alias: Existing\n  mode: single\n", encoding="utf-8")
            new_text = self.app._append_yaml_block(path, "- alias: Added\n  mode: single\n")

        self.assertEqual(new_text, "- alias: Existing\n  mode: single\n- alias: Added\n  mode: single\n")

    def test_transaction_backup_and_finish_record_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data_file = root / "scripts.yaml"
            data_file.write_text("test:\n  alias: Before\n", encoding="utf-8")
            original_tx_dir = self.app.HA_EXPERT_TX_DIR
            self.app.HA_EXPERT_TX_DIR = root / "transactions"
            try:
                tx = self.app._create_tx("unit-test", [data_file], {"case": "backup"})
                data_file.write_text("test:\n  alias: After\n", encoding="utf-8")
                tx = self.app._finish_tx(tx)
                backup_text = Path(tx["files"][0]["backup"]).read_text(encoding="utf-8")
            finally:
                self.app.HA_EXPERT_TX_DIR = original_tx_dir

        self.assertEqual(backup_text, "test:\n  alias: Before\n")
        self.assertTrue(tx["files"][0]["before_sha256"])
        self.assertTrue(tx["files"][0]["after_sha256"])
        self.assertNotEqual(tx["files"][0]["before_sha256"], tx["files"][0]["after_sha256"])


if __name__ == "__main__":
    unittest.main()
