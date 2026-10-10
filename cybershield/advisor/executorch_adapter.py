from pathlib import Path
class ExecuTorchLlamaAdapter:
 def __init__(self,path='models/llama/cybershield-llama.pte'): self.path=Path(path)
 @property
 def available(self): return self.path.exists()
 def advise(self,prompt):
  if not self.available: raise RuntimeError('Real ExecuTorch Llama .pte is not installed.')
  raise NotImplementedError('Use the selected ExecuTorch Llama runtime/LlmModule for text generation; do not fake generation in Python.')
