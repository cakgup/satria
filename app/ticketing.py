from __future__ import annotations

from datetime import datetime
from pathlib import Path
import hashlib

from sqlalchemy.orm import Session

from .models import Asset, Finding, TicketActivity, TicketCase, TicketEvidence, TicketTask
from .soc import MANUAL_PLAYBOOKS, SOC_DEMO_USERS, default_soc_id_for_case


def create_ticket_for_finding(db: Session, finding: Finding, asset: Asset, sync_mode: str) -> TicketCase:
    existing = finding.ticket_case
    if existing:
        return existing

    case = TicketCase(
        finding_id=finding.id,
        asset_id=asset.id,
        provider="dfir-iris",
        case_kind="finding",
        incident_type="scanner-finding",
        title=_finding_case_title(finding, asset),
        description=_finding_case_description(finding, asset),
        priority=_priority_from_severity(finding.severity_normalized),
        status="Open",
        current_role="L1",
        current_owner=SOC_DEMO_USERS["L1"],
        playbook="SOC-VULNERABILITY-REMEDIATION",
        source_channel=f"SATRIA/{finding.scanner}",
        organization_unit=asset.environment,
        reporter="SATRIA scanner",
        remote_case_soc_id=f"SATRIA-FINDING-{finding.id}",
        sync_mode=sync_mode,
        last_sync_status="pending",
    )
    db.add(case)
    db.flush()

    add_ticket_task(
        db,
        case,
        title=f"Validate finding {finding.id} and confirm impact",
        description=_task_description_for_finding("L1", finding, asset),
        role="L1",
        assignee=SOC_DEMO_USERS["L1"],
        tags=["triage", "scanner"],
        sync_mode=sync_mode,
        sort_order=10,
    )
    add_ticket_task(
        db,
        case,
        title="Coordinate remediation and retest",
        description=_task_description_for_finding("L2", finding, asset),
        role="L2",
        assignee=SOC_DEMO_USERS["L2"],
        tags=["remediation", "validation"],
        sync_mode=sync_mode,
        sort_order=20,
    )
    add_ticket_task(
        db,
        case,
        title="Approve closure and document hardening",
        description=_task_description_for_finding("L3", finding, asset),
        role="L3",
        assignee=SOC_DEMO_USERS["L3"],
        tags=["closure", "lessons-learned"],
        sync_mode=sync_mode,
        sort_order=30,
    )

    add_ticket_evidence(
        db,
        case,
        filename=_evidence_filename_for_finding(finding),
        description=finding.evidence or finding.description or "Scanner evidence attached by SATRIA",
        source_path=finding.scan_job.raw_report_path if finding.scan_job else None,
        sync_mode=sync_mode,
    )

    add_ticket_activity(
        db,
        case,
        actor="SATRIA scanner",
        actor_role="system",
        activity_type="intake",
        message=f"Finding #{finding.id} diangkat menjadi case untuk triage dan remediation.",
    )
    return case


def create_manual_ticket_case(
    db: Session,
    *,
    asset: Asset,
    title: str,
    description: str,
    incident_type: str,
    priority: str,
    source_channel: str,
    organization_unit: str,
    reporter: str,
    playbook: str,
    status: str = "Open",
    current_role: str = "L1",
    current_owner: str | None = None,
    sync_mode: str = "manual",
    resolution_summary: str | None = None,
) -> TicketCase:
    case = TicketCase(
        asset_id=asset.id,
        provider="dfir-iris",
        case_kind="manual",
        incident_type=incident_type,
        title=title,
        description=description,
        priority=priority,
        status=status,
        source_channel=source_channel,
        organization_unit=organization_unit,
        reporter=reporter,
        current_role=current_role,
        current_owner=current_owner or SOC_DEMO_USERS.get(current_role, SOC_DEMO_USERS["L1"]),
        playbook=playbook,
        resolution_summary=resolution_summary,
        remote_case_soc_id="pending",
        sync_mode=sync_mode,
        last_sync_status="pending",
    )
    db.add(case)
    db.flush()
    case.remote_case_soc_id = default_soc_id_for_case(case)
    return case


def create_manual_case_from_playbook(db: Session, *, asset: Asset, playbook_key: str, reporter: str, organization_unit: str | None = None) -> TicketCase:
    template = MANUAL_PLAYBOOKS[playbook_key]
    case = create_manual_ticket_case(
        db,
        asset=asset,
        title=template["title"],
        description=template["description"],
        incident_type=template["incident_type"],
        priority=template["priority"],
        source_channel=template["source_channel"],
        organization_unit=organization_unit or template["organization_unit"],
        reporter=reporter,
        playbook=template["playbook"],
        current_role="L1",
        current_owner=SOC_DEMO_USERS["L1"],
        sync_mode="manual",
        resolution_summary=template["resolution_summary"],
    )

    for index, (role, assignee, description) in enumerate(template["tasks"], start=1):
        add_ticket_task(
            db,
            case,
            title=f"{role} - {description.split(',')[0]}",
            description=description,
            role=role,
            assignee=assignee,
            tags=[template["incident_type"], role.lower()],
            sync_mode="manual",
            sort_order=index * 10,
        )

    for actor, role, activity_type, message in template["activities"]:
        add_ticket_activity(
            db,
            case,
            actor=actor,
            actor_role=role,
            activity_type=activity_type,
            message=message,
        )

    add_ticket_evidence(
        db,
        case,
        filename=f"{playbook_key}-initial-report.txt",
        description="Manual evidence placeholder created for SOC demonstration workflow.",
        source_path=_ensure_manual_evidence_file(playbook_key, template["description"]),
        sync_mode="manual",
    )
    return case


def seed_demo_manual_cases(db: Session, asset_lookup: dict[str, Asset]) -> list[TicketCase]:
    created: list[TicketCase] = []
    if not asset_lookup:
        return created

    target_asset = asset_lookup.get("Red Team Console") or next(iter(asset_lookup.values()))
    for playbook_key in MANUAL_PLAYBOOKS:
        existing = db.query(TicketCase).filter(
            TicketCase.case_kind == "manual",
            TicketCase.playbook == MANUAL_PLAYBOOKS[playbook_key]["playbook"],
        ).first()
        if existing:
            continue
        created.append(
            create_manual_case_from_playbook(
                db,
                asset=target_asset,
                playbook_key=playbook_key,
                reporter="SOC demo operator",
                organization_unit=MANUAL_PLAYBOOKS[playbook_key]["organization_unit"],
            )
        )
    return created


def add_ticket_task(
    db: Session,
    case: TicketCase,
    *,
    title: str,
    description: str | None,
    role: str | None,
    assignee: str | None,
    tags: list[str] | None,
    sync_mode: str,
    sort_order: int = 0,
) -> TicketTask:
    task = TicketTask(
        ticket_case_id=case.id,
        title=title,
        description=description,
        role=role,
        assignees=assignee,
        tags=",".join(tags) if tags else None,
        status="To be done",
        sync_mode=sync_mode,
        sort_order=sort_order,
    )
    db.add(task)
    return task


def add_ticket_evidence(
    db: Session,
    case: TicketCase,
    *,
    filename: str,
    description: str | None,
    source_path: str | None,
    sync_mode: str,
) -> TicketEvidence:
    content_hash, file_size = _hash_and_size_from_path_or_text(source_path, description)
    evidence = TicketEvidence(
        ticket_case_id=case.id,
        filename=filename,
        description=description,
        file_hash=content_hash,
        file_size=file_size,
        source_path=source_path,
        sync_mode=sync_mode,
    )
    db.add(evidence)
    return evidence


def add_ticket_activity(
    db: Session,
    case: TicketCase,
    *,
    actor: str,
    actor_role: str | None,
    activity_type: str,
    message: str,
) -> TicketActivity:
    activity = TicketActivity(
        ticket_case_id=case.id,
        actor=actor,
        actor_role=actor_role,
        activity_type=activity_type,
        message=message,
    )
    db.add(activity)
    case.updated_at = datetime.utcnow()
    return activity


def update_ticket_case(case: TicketCase, *, status: str, current_role: str, current_owner: str, resolution_summary: str | None):
    case.status = status
    case.current_role = current_role
    case.current_owner = current_owner
    if resolution_summary:
        case.resolution_summary = resolution_summary
    case.updated_at = datetime.utcnow()


def _priority_from_severity(severity: str) -> str:
    return {
        "Critical": "critical",
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Informational": "low",
    }.get(severity, "medium")


def _ensure_manual_evidence_file(playbook_key: str, content: str) -> str:
    evidence_dir = Path("/data/reports/manual-evidence")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_dir / f"{playbook_key}-initial-report.txt"
    if not evidence_path.exists():
        evidence_path.write_text(content, encoding="utf-8")
    return str(evidence_path)


def _finding_case_title(finding: Finding, asset: Asset) -> str:
    return f"[{finding.severity_normalized}] {asset.name} - {finding.title[:140]}"


def _finding_case_description(finding: Finding, asset: Asset) -> str:
    parts = [
        f"Asset: {asset.name} ({asset.asset_type})",
        f"Target: {asset.target}",
        f"Environment: {asset.environment}",
        f"Scanner: {finding.scanner}",
        f"Type: {finding.finding_type}",
        f"Severity: {finding.severity_normalized}",
        f"Risk Score: {finding.risk_score}",
    ]
    if finding.cve:
        parts.append(f"CVE: {finding.cve}")
    if finding.cwe:
        parts.append(f"CWE: {finding.cwe}")
    if finding.description:
        parts.append(f"Description: {finding.description}")
    if finding.recommendation:
        parts.append(f"Recommendation: {finding.recommendation}")
    return "\n".join(parts)


def _task_description_for_finding(role: str, finding: Finding, asset: Asset) -> str:
    base = finding.recommendation or "Validate finding, assign owner, remediate, and retest."
    return (
        f"{role} handling finding #{finding.id} on {asset.name}.\n"
        f"Current finding status: {finding.status}\n"
        f"Recommended next step: {base}"
    )


def _evidence_filename_for_finding(finding: Finding) -> str:
    if finding.scan_job and finding.scan_job.raw_report_path:
        return Path(finding.scan_job.raw_report_path).name
    return f"finding-{finding.id}-evidence.txt"


def _hash_and_size_from_path_or_text(source_path: str | None, fallback_text: str | None) -> tuple[str | None, int | None]:
    if source_path:
        path = Path(source_path)
        if path.exists() and path.is_file():
            content = path.read_bytes()
            return hashlib.sha256(content).hexdigest(), len(content)
    if fallback_text:
        content = fallback_text.encode("utf-8")
        return hashlib.sha256(content).hexdigest(), len(content)
    return None, None
