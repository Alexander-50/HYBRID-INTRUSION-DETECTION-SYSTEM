from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class SIDSEvent(BaseModel):
    timestamp: str
    src_ip: str
    src_port: Optional[int] = None
    dest_ip: str
    dest_port: Optional[int] = None
    signature: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[int] = None
    type: str # DOS, RECON
    subtype: Optional[str] = None
    source: str # "SIDS"
    label: Optional[str] = None

class AIDSEvent(BaseModel):
    timestamp: Optional[str] = None
    src_ip: str
    dest_ip: str
    type: str # DOS, RECON
    subtype: Optional[str] = None
    source: str # "AIDS"
    confidence: float = Field(..., ge=0.0, le=1.0)

class NormalizedEvent(BaseModel):
    timestamp: str
    src_ip: str
    src_port: Optional[int] = None
    dest_ip: str
    dest_port: Optional[int] = None
    type: str
    subtype: Optional[str] = None
    severity: Optional[int] = None
    signature: Optional[str] = None
    category: Optional[str] = None
    source: str
    confidence: Optional[float] = None

class FinalAlert(BaseModel):
    timestamp: str
    src_ip: str
    src_port: Optional[int] = None
    dest_ip: str
    dest_port: Optional[int] = None
    type: str
    subtype: Optional[str] = None
    severity: Optional[int] = None
    signature: Optional[str] = None
    category: Optional[str] = None
    detected_by: List[str] # ["SIDS", "AIDS"]
    alert: bool = True
    confidence: Optional[float] = None
    count: int = 1
