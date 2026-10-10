from cybershield.advisor.llama_advisor import LlamaAdvisor

def advise(r):
    out=LlamaAdvisor().advise(r)
    if out:
        out.update({'offline':True,'engine':'llama-executorch'})
        return out
    return {'summary':f"{r.get('threat_type')} detected with {r.get('severity')} severity and risk score {r.get('risk_score',0):.0f}/100.",'why':r.get('evidence',[]),'actions':r.get('recommended_actions',[]),'offline':True,'engine':'local-grounded-fallback'}
