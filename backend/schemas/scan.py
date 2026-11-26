from pydantic import BaseModel
from typing import List, Optional

class ScanRequest(BaseModel):
    target_ip: str
    scan_id: Optional[str] = None
    user_id: Optional[str] = None
    passive: Optional[bool] = False
    interface: Optional[str] = "all"


class CVELookupRequest(BaseModel):
    servicio: str
    version: str


class BatchDeleteRequest(BaseModel):
    scan_ids: List[str]


class BridgeBindRequest(BaseModel):
    target: str
    interface: Optional[str] = None
