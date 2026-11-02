import unittest
from pathlib import Path
from unittest.mock import patch
from c07_macro100_controller import read_original_telemetry
from c07_macro100_domain import MissingEvidence


class TelemetrySourceTests(unittest.TestCase):
    def read(self, raw):
        with patch.object(Path, 'is_file', return_value=True), \
             patch.object(Path, 'is_symlink', return_value=False), \
             patch.object(Path, 'read_bytes', return_value=raw):
            return read_original_telemetry(Path('/original/telemetry.jsonl'))

    def test_actual_timestamps_recompute_wall_not_productive_time(self):
        raw=b'{"run_started_at":"2026-10-11T22:00:59+00:00","run_finished_at":"2026-10-11T22:09:57+00:00","wall_elapsed_seconds":99999,"end_reason":"EXECUTION_BUDGET"}\n'
        r=self.read(raw)['records'][0]
        self.assertEqual(r['wall_elapsed_recomputed_seconds'],538)
        self.assertIsNone(r['productive_seconds'])
        self.assertEqual(r['provider_termination_cause'],'UNKNOWN')
        self.assertEqual(r['original_claims']['wall_elapsed_seconds'],99999)

    def test_controller_close_is_not_provider_final_event(self):
        r=self.read(b'{"controller_closed_at":"2026-10-12T00:34:45Z","end_reason_evidence_source":"SELF_REPORTED","actual_final_event_at":null}\n')
        self.assertFalse(r['provider_final_event_verified'])
        self.assertIsNone(r['records'][0]['wall_elapsed_recomputed_seconds'])

    def test_ambiguous_and_duplicate_fields_do_not_pass(self):
        for raw in (b'{"run_started_at":"a","run_start_utc":"b"}\n',
                    b'{"run_id":1,"run_id":2}\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):self.read(raw)


if __name__=='__main__':unittest.main()
