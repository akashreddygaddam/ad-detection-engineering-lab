import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "src" / "analyze_events.py"
spec = importlib.util.spec_from_file_location("analyze_events", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class DetectionTests(unittest.TestCase):
    def test_kerberos_ticket_event_is_reviewed(self):
        result = module.analyze({"event_id": 4769})
        self.assertTrue(any("Kerberos" in message for _, message in result))

    def test_replication_like_event_is_high(self):
        result = module.analyze({"event_id": 4662, "access_mask": "0x100"})
        self.assertEqual(result[0][0], "HIGH")

    def test_encoded_powershell_is_flagged(self):
        result = module.analyze({
            "event_id": 1,
            "image": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -EncodedCommand AAA="
        })
        self.assertTrue(any("encoded-command" in message for _, message in result))

    def test_unrelated_event_is_quiet(self):
        self.assertEqual(module.analyze({"event_id": 4624}), [])

if __name__ == "__main__":
    unittest.main()
