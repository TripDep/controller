"""R141: retain frozen first200 unchanged while gathering 20 A/C source probes."""
import unittest
from c07_positive200_evidence import R122_FROZEN_IDS
from c07_a10_c10_original_evidence import IDS
from approved_validators import REVIEWED

class FrozenOriginalCohort(unittest.TestCase):
    def test_exact_noncohort_two_are_already_reviewed(self):
        out=set(IDS)-set(R122_FROZEN_IDS)
        self.assertEqual(out,{'AAA-200-A-008','AAA-200-A-009'})
        self.assertEqual(len(set(IDS)&set(R122_FROZEN_IDS)),18)
        self.assertTrue(out<=set(REVIEWED))
    def test_original_frozen200_is_never_resized(self):
        self.assertEqual(len(R122_FROZEN_IDS),200)
        self.assertEqual(len(set(R122_FROZEN_IDS)),200)
        self.assertEqual(len(IDS),20)
    def test_20_literally_distinct_source_domains_remain(self):
        from c07_a10_c10_original_evidence import TEXT
        self.assertEqual(len(TEXT),20)
        self.assertEqual(set(TEXT),set(range(1,11))|set(range(21,31)))

if __name__=='__main__':unittest.main()
