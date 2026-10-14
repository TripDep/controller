"""Current canonical inventory / genuine UNKNOWN decision; no invented PASS."""
import argparse,json,os,hashlib
from broker_live_review import ReadOnlyAPI,decode_file
import family_coverage as f
import supervisor_context as context
import supervisor_judgment as judgment
from git_judgment_origin import OriginAPI,PRIVATE_REPO_SHA
from broker_authority_alignment_v4 import strict_json

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--ref',required=True);p.add_argument('--master-sha',required=True);args=p.parse_args(argv)
    try:
        api=OriginAPI(os.environ['GH_REVIEW_TOKEN'],os.environ['GITHUB_REPOSITORY'])
        judgment.need(hashlib.sha256(api.repository.encode()).hexdigest()==PRIVATE_REPO_SHA,'JUDGMENT_REPOSITORY')
        judgment.need(f.re.fullmatch('[a-f0-9]{40}',args.ref),'JUDGMENT_IMMUTABLE_REF')
        raw={k:decode_file(api.call('GET','/contents/'+path+'?ref='+args.ref),path) for k,path in f.SOURCES.items()}
        inv=f.build_inventory(raw,args.master_sha);contexts={}
        for role,path in context.PATHS.items():contexts[role]=context.validate(strict_json(decode_file(api.call('GET','/contents/'+path+'?ref='+args.ref),path),max_size=32000))
        # Explicit diagnostic template. Not a claim that a real vegetation asset
        # reached P8, and never eligible for an operational action.
        dep=next(iter(contexts['rescue']['dependencies']))
        work={'work_item_sha256':judgment.digest('C07_FULL_INVENTORY_DIAGNOSTIC'),'attempt_id':judgment.digest(args.ref),'operation_sha256':judgment.digest('C07_DIAGNOSTIC_ONLY'),'attempt_number':1,'previous_attempt_id':None,'phase':'P8','asset_type':'vegetation','profiles':['FOLIAGE_PROFILE'],'master_sha256':args.master_sha,'work_dependencies':{dep:contexts['rescue']['dependencies'][dep]},'asset_specific_extensions_verified':False,'guardian_required':True,'mode':'DIAGNOSTIC_ONLY','closure_requested':False}
        result=judgment.judge(inv,work,{},judgment.NativeRuleBackend(api,{}),current_contexts=contexts)
        judgment.need(result['family_count']==inv['family_count'] and result['rule_count']==inv['rule_count'] and sum(result['counts'].values())==inv['rule_count'] and result['counts']['PASS']==0 and result['counts']['FAIL']==0 and result['counts']['UNKNOWN']>0,'JUDGMENT_OMITTED_ID')
        judgment.need(result['advancement_authorized'] is False and result['phase_ready'] is False,'JUDGMENT_FALSE_ADVANCEMENT')
        print('C07_NATIVE_PROCESS_JUDGMENT:'+json.dumps(result,sort_keys=True))
        print('C07_JUDGMENT_SUMMARY:'+json.dumps({k:result[k] for k in ('action','counts','family_count','rule_count','blockers','advancement_authorized','mode','decision_sha256')},sort_keys=True))
        try:judgment._consume_checked(result,result,work,work['operation_sha256'],set())
        except judgment.Blocked as exc:
            judgment.need(str(exc)=='JUDGMENT_ADVANCEMENT_DENIED','JUDGMENT_WRONG_DENIAL');print('C07_STOP_CONSUMPTION_REJECTED:'+str(exc))
        else:raise judgment.Blocked('JUDGMENT_STOP_CONSUMED')
        return 0
    except (ValueError,KeyError,TypeError,OSError) as exc:print('C07_JUDGMENT_ERROR:'+str(exc));return 1
if __name__=='__main__':raise SystemExit(main())
