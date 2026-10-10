"""Grounded Llama advisor boundary.

The advisor receives only structured detector evidence. It never changes the detector verdict.
For real ExecuTorch generation, set CYBERSHIELD_LLAMA_RUNNER to a locally built ExecuTorch LLM runner.
"""
import json, os, subprocess
from pathlib import Path

class LlamaAdvisor:
    def __init__(self,pte='models/llama/cybershield-llama.pte',runner=None,timeout=60):
        self.pte=Path(pte); self.runner=runner or os.getenv('CYBERSHIELD_LLAMA_RUNNER'); self.timeout=int(timeout)
    @property
    def available(self): return bool(self.runner and self.pte.exists() and Path(self.runner).exists())
    def build_prompt(self,result):
        evidence={'threat_type':result.get('threat_type'),'severity':result.get('severity'),'risk_score':result.get('risk_score'),'confidence':result.get('confidence'),'evidence':result.get('evidence',[]),'recommended_actions':result.get('recommended_actions',[])}
        return ('You are CyberShield AI, a defensive security advisor. Explain ONLY the supplied evidence. '
                'Do not invent indicators, commands, victims, or certainty. Return concise JSON with summary, why, actions, caution.\n'
                + json.dumps(evidence,ensure_ascii=False))
    def advise(self,result):
        prompt=self.build_prompt(result)
        if not self.available: return None
        p=subprocess.run([self.runner,'--model',str(self.pte),'--prompt',prompt],capture_output=True,text=True,timeout=self.timeout,check=True)
        return json.loads(p.stdout)
