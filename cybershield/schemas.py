from dataclasses import dataclass,asdict
@dataclass
class DetectionResult:
    threat_type:str; severity:str; risk_score:float; confidence:float; evidence:list[str]; recommended_actions:list[str]; model_version:str='heuristic-1.0'
    def to_dict(self): return asdict(self)
