from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class AssetCreate(BaseModel):
    name: str
    asset_type: str
    target: str
    environment: str = 'development'
    criticality: str = 'medium'
    owner: Optional[str] = None
    technical_pic: Optional[str] = None

class AssetOut(AssetCreate):
    id: int
    is_active: bool
    created_at: datetime
    model_config = {'from_attributes': True}

class ScanCreate(BaseModel):
    asset_id: int
    profile: str = Field(default='quick_container')

class ScanOut(BaseModel):
    id: int
    asset_id: int
    profile: str
    scanner: str
    status: str
    message: Optional[str] = None
    raw_report_path: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    model_config = {'from_attributes': True}

class FindingOut(BaseModel):
    id: int
    asset_id: int
    scan_job_id: int
    scanner: str
    finding_type: str
    title: str
    severity_normalized: str
    cve: Optional[str] = None
    risk_score: int
    status: str
    iris_alert_id: Optional[str] = None
    model_config = {'from_attributes': True}
