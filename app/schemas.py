from pydantic import AliasChoices, BaseModel, Field
from typing import Optional
from datetime import datetime
from typing import Any

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


class ReleaseIntakeCreate(BaseModel):
    asset_id: int | None = None
    asset_name: str
    asset_code: str | None = None
    asset_type: str = 'container_image'
    image_ref: str = Field(validation_alias=AliasChoices('image_ref', 'image'))
    target: str | None = None
    environment: str = 'development'
    environment_target: str | None = None
    criticality: str = 'medium'
    owner: str | None = None
    technical_pic: str | None = None
    release_version: str | None = None
    image_digest: str | None = None
    git_commit: str | None = None
    build_number: str | None = None
    requested_by: str | None = None
    source_registry: str | None = None
    risk_acceptance_ref: str | None = None
    gate_override_decision: str | None = None
    metadata: dict[str, Any] | None = None


class ReleaseIntakeOut(BaseModel):
    asset_id: int
    release_id: int
    asset_name: str
    asset_code: str | None = None
    release_version: str | None = None
    image_ref: str
    image_digest: str | None = None
    git_commit: str | None = None
    build_number: str | None = None
    requested_by: str | None = None
    environment_target: str | None = None
    risk_acceptance_ref: str | None = None
    gate_override_decision: str | None = None
    created_at: datetime


class PipelineScanCreate(BaseModel):
    asset_id: int | None = None
    release_id: int | None = None
    image_ref: str | None = None
    profile: str = Field(default='quick_container')
    requested_by: str | None = None
    build_number: str | None = None


class PipelineSeveritySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    total: int = 0


class PipelineScanStatusOut(BaseModel):
    scan_id: int
    asset_id: int
    asset_name: str
    release_id: int | None = None
    profile: str
    scanner: str
    status: str
    gate_decision: str
    requested_by: str | None = None
    build_number: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    message: str | None = None


class PipelineScanResultOut(BaseModel):
    scan_id: int
    asset_id: int
    asset_name: str
    release_id: int | None = None
    profile: str
    scanner: str
    status: str
    mode: str
    decision: str
    gate_decision: str
    policy_name: str
    severity_summary: PipelineSeveritySummary
    total_findings: int
    report_path: str | None = None
    report_url: str | None = None
    finding_url: str | None = None
    publish_ticket_url: str | None = None
    message: str | None = None
    risk_acceptance_ref: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class PipelinePublishTicketRequest(BaseModel):
    target_system: str = Field(default='iris')
    severity_filter: list[str] | None = None
    assign_to: str | None = None
    due_date: datetime | None = None


class PipelinePublishTicketOut(BaseModel):
    scan_id: int
    published_count: int
    remote_ids: list[str]
    status: str
