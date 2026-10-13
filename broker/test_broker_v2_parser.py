import json
import tempfile
import unittest
from pathlib import Path
import git_release_broker_v2 as broker

class StrictBrokerParserTests(unittest.TestCase):
    def with_text(self, data):
        folder=tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path=Path(folder.name)/'payload.json'
        path.write_text(data,encoding='utf-8')
        return path
    def test_duplicate_policy_key_blocked(self):
        p=self.with_text('{"enabled": false, "enabled": true}')
        with self.assertRaisesRegex(broker.Blocked,'JSON_DUPLICATE_KEY'):
            broker.strict_json_file(p)
    def test_duplicate_inner_authorization_key_blocked(self):
        p=self.with_text('{"authorization":{"pr_number":1,"pr_number":2},"signature_base64":""}')
        with self.assertRaisesRegex(broker.Blocked,'JSON_DUPLICATE_KEY'):
            broker.read_request(p)
    def test_nan_rejected(self):
        p=self.with_text('{"a":NaN}')
        with self.assertRaisesRegex(broker.Blocked,'BROKER_JSON_NONFINITE_NUMBER'):
            broker.strict_json_file(p)
    def test_infinity_rejected(self):
        p=self.with_text('{"a":Infinity}')
        with self.assertRaisesRegex(broker.Blocked,'BROKER_JSON_NONFINITE_NUMBER'):
            broker.strict_json_file(p)
    def test_symlink_input_blocked(self):
        with tempfile.TemporaryDirectory() as folder:
            folder=Path(folder)
            dest=folder/'real.json';dest.write_text('{}')
            link=folder/'link.json';link.symlink_to(dest)
            with self.assertRaisesRegex(broker.Blocked,'BROKER_CONFIG_FILE_UNSAFE'):
                broker.strict_json_file(link)
    def test_large_input_blocked(self):
        p=self.with_text('{"data":"'+'a'*8192+'"}')
        with self.assertRaisesRegex(broker.Blocked,'BROKER_CONFIG_FILE_TOO_LARGE'):
            broker.strict_json_file(p)
    def test_well_formed_json_accepted(self):
        p=self.with_text('{"a":1,"b":{"c":2}}')
        self.assertEqual(broker.strict_json_file(p),{'a':1,'b':{'c':2}})

if __name__=='__main__':unittest.main(verbosity=2)
