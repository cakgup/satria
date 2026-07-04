from datetime import datetime
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base

class Asset(Base):
    __tablename__ = 'assets'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(200), index=True)
    asset_type: Mapped[str] = mapped_column(String(50), index=True)
    target: Mapped[str] = mapped_column(Text)
    environment: Mapped[str] = mapped_column(String(50), default='development')
    criticality: Mapped[str] = mapped_column(String(20), default='medium')
    owner: Mapped[str | None] = mapped_column(String(200), nullable=True)
    technical_pic: Mapped[str | None] = mapped_column(String(200), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scans: Mapped[list['ScanJob']] = relationship(back_populates='asset')
    findings: Mapped[list['Finding']] = relationship(back_populates='asset')
    ticket_cases: Mapped[list['TicketCase']] = relationship(back_populates='asset')
    releases: Mapped[list['ReleaseArtifact']] = relationship(back_populates='asset')


class ScanAllowlistEntry(Base):
    __tablename__ = 'scan_allowlist_entries'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    rule: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ReleaseArtifact(Base):
    __tablename__ = 'release_artifacts'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey('assets.id'), index=True)
    asset_code: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    release_version: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    image_ref: Mapped[str] = mapped_column(Text)
    image_digest: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    git_commit: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    build_number: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    requested_by: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    environment_target: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    source_registry: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    asset: Mapped['Asset'] = relationship(back_populates='releases')
    scans: Mapped[list['ScanJob']] = relationship(back_populates='release')


class ScanJob(Base):
    __tablename__ = 'scan_jobs'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey('assets.id'), index=True)
    release_id: Mapped[int | None] = mapped_column(ForeignKey('release_artifacts.id'), nullable=True, index=True)
    profile: Mapped[str] = mapped_column(String(80), index=True)
    scanner: Mapped[str] = mapped_column(String(80), index=True)
    status: Mapped[str] = mapped_column(String(30), default='queued', index=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_report_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_visible: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    asset: Mapped['Asset'] = relationship(back_populates='scans')
    release: Mapped['ReleaseArtifact | None'] = relationship(back_populates='scans')
    findings: Mapped[list['Finding']] = relationship(back_populates='scan_job')

class Finding(Base):
    __tablename__ = 'findings'
    __table_args__ = (UniqueConstraint('dedup_key', name='uq_findings_dedup_key'),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey('assets.id'), index=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey('scan_jobs.id'), index=True)
    scanner: Mapped[str] = mapped_column(String(80), index=True)
    finding_type: Mapped[str] = mapped_column(String(80), index=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity_original: Mapped[str] = mapped_column(String(30), default='UNKNOWN')
    severity_normalized: Mapped[str] = mapped_column(String(30), default='Informational', index=True)
    cve: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    cwe: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    package_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    installed_version: Mapped[str | None] = mapped_column(String(200), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(200), nullable=True)
    affected_component: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    status: Mapped[str] = mapped_column(String(30), default='Open', index=True)
    dedup_key: Mapped[str] = mapped_column(String(500), index=True)
    iris_alert_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    first_detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    asset: Mapped['Asset'] = relationship(back_populates='findings')
    scan_job: Mapped['ScanJob'] = relationship(back_populates='findings')
    ticket_case: Mapped['TicketCase | None'] = relationship(back_populates='finding')

class AuditLog(Base):
    __tablename__ = 'audit_logs'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(120), default='system')
    action: Mapped[str] = mapped_column(String(120))
    object_type: Mapped[str] = mapped_column(String(120))
    object_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TicketCase(Base):
    __tablename__ = 'ticket_cases'
    __table_args__ = (UniqueConstraint('finding_id', name='uq_ticket_cases_finding_id'),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey('findings.id'), nullable=True, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey('assets.id'), index=True)
    provider: Mapped[str] = mapped_column(String(40), default='dfir-iris')
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default='Open', index=True)
    sync_mode: Mapped[str] = mapped_column(String(20), default='stub')
    remote_alert_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    remote_case_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    remote_customer_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    remote_case_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    remote_case_soc_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_sync_status: Mapped[str] = mapped_column(String(40), default='pending')
    last_sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    case_kind: Mapped[str] = mapped_column(String(30), default='finding', index=True)
    incident_type: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    priority: Mapped[str] = mapped_column(String(30), default='medium', index=True)
    source_channel: Mapped[str | None] = mapped_column(String(80), nullable=True)
    organization_unit: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reporter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    current_role: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    current_owner: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    playbook: Mapped[str | None] = mapped_column(String(120), nullable=True)
    resolution_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    remote_notes_directory_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    remote_evidence_folder_id: Mapped[str | None] = mapped_column(String(120), nullable=True)

    finding: Mapped['Finding'] = relationship(back_populates='ticket_case')
    asset: Mapped['Asset'] = relationship(back_populates='ticket_cases')
    tasks: Mapped[list['TicketTask']] = relationship(back_populates='ticket_case', cascade='all, delete-orphan')
    evidences: Mapped[list['TicketEvidence']] = relationship(back_populates='ticket_case', cascade='all, delete-orphan')
    activities: Mapped[list['TicketActivity']] = relationship(back_populates='ticket_case', cascade='all, delete-orphan')


class TicketTask(Base):
    __tablename__ = 'ticket_tasks'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ticket_case_id: Mapped[int] = mapped_column(ForeignKey('ticket_cases.id'), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default='To be done')
    assignees: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)
    sync_mode: Mapped[str] = mapped_column(String(20), default='stub')
    remote_task_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    role: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    ticket_case: Mapped['TicketCase'] = relationship(back_populates='tasks')


class TicketEvidence(Base):
    __tablename__ = 'ticket_evidences'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ticket_case_id: Mapped[int] = mapped_column(ForeignKey('ticket_cases.id'), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    sync_mode: Mapped[str] = mapped_column(String(20), default='stub')
    remote_evidence_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    remote_file_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)

    ticket_case: Mapped['TicketCase'] = relationship(back_populates='evidences')


class TicketActivity(Base):
    __tablename__ = 'ticket_activities'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ticket_case_id: Mapped[int] = mapped_column(ForeignKey('ticket_cases.id'), index=True)
    actor: Mapped[str] = mapped_column(String(120), default='system')
    actor_role: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    activity_type: Mapped[str] = mapped_column(String(50), default='note', index=True)
    message: Mapped[str] = mapped_column(Text)
    remote_note_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    ticket_case: Mapped['TicketCase'] = relationship(back_populates='activities')
