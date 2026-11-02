import tempfile
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path
from real_work_intake import sha
from c07_macro100_controller import acquire_registered_copies
from c07_macro100_domain import MissingEvidence


@contextmanager
def copy_directory():
    # Default directory permissions inherit the workspace ACL on Windows.
    directory = Path(tempfile.gettempdir()) / ('c07-original-copy-'+uuid.uuid4().hex)
    directory.mkdir()
    try:
        yield directory
    finally:
        for name in ('current.md', 'model.glb'):
            path = directory/name
            if path.exists():
                path.unlink()
        directory.rmdir()


class OriginalCopyTests(unittest.TestCase):
    def test_same_historical_path_keeps_two_distinct_revisions(self):
        a,b=b'old original',b'new original'
        snapshot={'schema':'gg-c07-persisted-controller-snapshot-v1','asset_state':{'artifacts':[
            {'path':'/cloud/checklist.md','step':'1','sha256':sha(a),'size_bytes':len(a)},
            {'path':'/cloud/checklist.md','step':'2','sha256':sha(b),'size_bytes':len(b)}]}}
        with copy_directory() as directory:
            p=Path(directory)/'current.md';p.write_bytes(b)
            result=acquire_registered_copies(snapshot,{sha(b):p})
            self.assertEqual([r['acquisition'] for r in result['registrations']],
                             ['MISSING','ORIGINAL_BYTES_VERIFIED'])
            self.assertEqual(result['original_bytes'],{sha(b):b})
            self.assertFalse(result['advancement_authorized'])

    def test_matching_name_or_size_cannot_replace_registered_content(self):
        original=b'original';altered=b'forged!!'
        snapshot={'schema':'gg-c07-persisted-controller-snapshot-v1','asset_state':{'artifacts':[
            {'path':'/cloud/model.glb','step':'1','sha256':sha(original),'size_bytes':len(original)}]}}
        with copy_directory() as directory:
            p=Path(directory)/'model.glb';p.write_bytes(altered)
            with self.assertRaisesRegex(MissingEvidence,'differs from Controller'):
                acquire_registered_copies(snapshot,{sha(original):p})

    def test_unhashed_registration_cannot_be_adopted_as_evidence(self):
        snapshot={'schema':'gg-c07-persisted-controller-snapshot-v1','asset_state':{'artifacts':[
            {'path':'/cloud/preview.png','step':'1'}]}}
        result=acquire_registered_copies(snapshot,{})
        self.assertEqual(result['registrations'][0]['acquisition'],'UNBOUND')
        self.assertEqual(result['original_bytes'],{})


if __name__=='__main__':unittest.main()
