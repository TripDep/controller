"""Native read-only source inventory audit and explicitly synthetic omissions."""
import argparse
import copy
import hashlib
import json
import os
import re
import family_coverage as coverage
from broker_live_review import ReadOnlyAPI, decode_file

REPO_SHA='ba6c371db01f88a9a16e02a03d673f320bd3c04adc3ebdff97b2ef102a188e70'

def audit(api,ref,master_sha,prove_omissions=False):
    coverage.need(hashlib.sha256(api.repository.encode()).hexdigest()==REPO_SHA,'SOURCE_REPOSITORY')
    coverage.need(isinstance(ref,str) and re.fullmatch('[a-f0-9]{40}',ref),'SOURCE_REF_NOT_IMMUTABLE')
    coverage.need(isinstance(master_sha,str) and coverage.HEX.fullmatch(master_sha),'SOURCE_MASTER_DIGEST_INVALID')
    raw={key:decode_file(api.call('GET','/contents/'+path+'?ref='+ref),path)
         for key,path in coverage.SOURCES.items()}
    inv=coverage.build_inventory(raw,master_sha)
    summary={k:inv[k] for k in ('schema','legacy_family_count','legacy_rule_count','family_count',
          'rule_count','explicit_r110_additions','aaa_section_count','coverage_scope',
          'asset_specific_context_extensions_verified','canonical_master_sha256','source_digests',
          'source_read_mode','library_live_read','asset_execution_passes','advancement_authorized')}
    summary['families']={name:len(ids) for name,ids in inv['families'].items()}
    summary['repository_ref']=ref
    print('C04_CANONICAL_SOURCE_INVENTORY:'+json.dumps(summary,sort_keys=True))
    if prove_omissions:
        # Fixture metadata exercises structure only, not actual rule/evidence
        # execution. It is never a completed work manifest or signed asset PASS.
        from test_family_coverage import synthetic_ledger
        ledger=synthetic_ledger(inv);context={'phase':'P8','asset_type':'vegetation','profiles':['FOLIAGE_PROFILE']}
        full=coverage.validate_coverage(inv,ledger,**context)
        assert full['advancement_authorized'] is False and full['actual_work_passes']==0
        counts={'families':0,'rules':0,'mg0':0}
        def refused(candidate,reason):
            try:coverage.validate_coverage(inv,candidate,**context)
            except coverage.Blocked as exc:
                coverage.need(str(exc).startswith(reason),'WRONG_OMISSION_FAILURE:'+str(exc));return
            raise coverage.Blocked('OMISSION_ACCEPTED:'+reason)
        for family,ids in inv['families'].items():
            missing=copy.deepcopy(ledger);missing['families'].pop(family)
            refused(missing,'LEDGER_FAMILY_COVERAGE');counts['families']+=1
            for rule in ids:
                missing=copy.deepcopy(ledger);missing['families'][family].pop(rule)
                refused(missing,'LEDGER_RULE_COVERAGE:');counts['rules']+=1
                missing=copy.deepcopy(ledger);missing['families'][family][rule].pop('mg0')
                refused(missing,'LEDGER_MG0_BINDING:');counts['mg0']+=1
        print('C04_SYNTHETIC_OMISSION_BLOCKS:'+json.dumps(counts,sort_keys=True))
        print('C04_NO_WORK_AUTHORIZATION:'+json.dumps(full,sort_keys=True))
    return summary

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--repository',required=True);p.add_argument('--ref',required=True)
    p.add_argument('--master-sha',required=True);p.add_argument('--prove-omissions',action='store_true');args=p.parse_args(argv)
    try:
        return 0 if audit(ReadOnlyAPI(os.environ.get('GH_REVIEW_TOKEN'),args.repository),args.ref,args.master_sha,args.prove_omissions) else 1
    except (ValueError,KeyError,TypeError,OSError) as exc:
        print('C04_COVERAGE_BLOCKED:'+str(exc));return 1

if __name__=='__main__':raise SystemExit(main())
