from typing import Optional
from pydantic import BaseModel


class RunRequest(BaseModel):
    raw_input: str


class HITLDecisionRequest(BaseModel):
    choice:            str
    approver:          str
    role:              Optional[str] = ""
    feedback:          Optional[str] = None
    extra_notes:       Optional[str] = None
    justification:     Optional[str] = None
    risk_acknowledged: Optional[bool] = False