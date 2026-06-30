from __future__ import annotations

import csv
import io
from math import pi
from collections import OrderedDict
from datetime import datetime
from typing import Iterable
from urllib.parse import quote_plus

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import Asset, Finding, ScanJob

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
STATUS_ORDER = ["Open", "Assigned", "In Progress", "Remediated", "Retest", "Closed", "False Positive", "Accepted Risk"]
SCANNER_ORDER = ["trivy", "syft", "grype", "zap", "openvas"]


def _ordered_counts(rows: Iterable[tuple[str | None, int]], order: list[str]) -> OrderedDict[str, int]:
    data = {k or "Unknown": int(v) for k, v in rows}
    result: OrderedDict[str, int] = OrderedDict()
    for key in order:
        result[key] = data.pop(key, 0)
    for key in sorted(data):
        result[key] = data[key]
    return result


def active_findings_query(db: Session):
    return (
        db.query(Finding)
        .join(Asset, Finding.asset_id == Asset.id)
        .join(ScanJob, Finding.scan_job_id == ScanJob.id)
        .filter(Asset.is_active == True, ScanJob.is_visible == True)  # noqa: E712
    )


def get_summary(db: Session) -> dict:
    active_findings = active_findings_query(db)
    severity = _ordered_counts(
        active_findings.with_entities(Finding.severity_normalized, func.count(Finding.id)).group_by(Finding.severity_normalized).all(),
        SEVERITY_ORDER,
    )
    status = _ordered_counts(
        active_findings.with_entities(Finding.status, func.count(Finding.id)).group_by(Finding.status).all(),
        STATUS_ORDER,
    )
    scanner = _ordered_counts(
        active_findings.with_entities(Finding.scanner, func.count(Finding.id)).group_by(Finding.scanner).all(),
        SCANNER_ORDER,
    )
    total_findings = sum(severity.values())
    open_findings = sum(v for k, v in status.items() if k not in {"Closed", "False Positive", "Accepted Risk"})
    critical_high = severity.get("Critical", 0) + severity.get("High", 0)
    completed_scans = db.query(ScanJob).filter(ScanJob.is_visible == True, ScanJob.status == "completed").count()  # noqa: E712
    failed_scans = db.query(ScanJob).filter(ScanJob.is_visible == True, ScanJob.status == "failed").count()  # noqa: E712

    top_assets = (
        db.query(Asset.name, func.count(Finding.id).label("total"), func.max(Finding.risk_score).label("max_risk"))
        .join(Finding, Finding.asset_id == Asset.id)
        .join(ScanJob, Finding.scan_job_id == ScanJob.id)
        .filter(Asset.is_active == True, ScanJob.is_visible == True)  # noqa: E712
        .group_by(Asset.id, Asset.name)
        .order_by(func.max(Finding.risk_score).desc(), func.count(Finding.id).desc())
        .limit(10)
        .all()
    )
    recent_scans = db.query(ScanJob).filter(ScanJob.is_visible == True).order_by(ScanJob.id.desc()).limit(20).all()  # noqa: E712
    latest_findings = active_findings.order_by(Finding.risk_score.desc(), Finding.id.desc()).limit(20).all()

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "assets": db.query(Asset).filter(Asset.is_active == True).count(),  # noqa: E712
        "scans": db.query(ScanJob).filter(ScanJob.is_visible == True).count(),  # noqa: E712
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "findings": total_findings,
        "open_findings": open_findings,
        "critical_high": critical_high,
        "severity": severity,
        "status": status,
        "scanner": scanner,
        "top_assets": [{"name": name, "total": total, "max_risk": max_risk} for name, total, max_risk in top_assets],
        "recent_scans": recent_scans,
        "latest_findings": latest_findings,
    }


def severity_pie_style(severity: dict[str, int]) -> str:
    return count_pie_style(
        severity,
        SEVERITY_ORDER,
        {
            "Critical": "#ef4444",
            "High": "#f97316",
            "Medium": "#facc15",
            "Low": "#3b82f6",
            "Informational": "#94a3b8",
        },
    )


def count_pie_segments(
    counts: dict[str, int],
    order: list[str],
    colors: dict[str, str],
    href_builder,
) -> list[dict[str, str | int | float]]:
    total = sum(counts.values())
    radius = 42.0
    circumference = 2 * pi * radius
    if total <= 0:
        return []

    segments: list[dict[str, str | int | float]] = []
    drawn = 0.0
    for key in order:
        value = counts.get(key, 0)
        if value <= 0:
            continue
        portion = value / total
        dash_length = portion * circumference
        segments.append({
            "label": key,
            "value": value,
            "color": colors.get(key, "#64748b"),
            "dasharray": f"{dash_length:.3f} {circumference:.3f}",
            "dashoffset": f"{-drawn:.3f}",
            "href": href_builder(key),
        })
        drawn += dash_length
    return segments


def severity_pie_segments(severity: dict[str, int]) -> list[dict[str, str | int | float]]:
    colors = {
        "Critical": "#ef4444",
        "High": "#f97316",
        "Medium": "#facc15",
        "Low": "#3b82f6",
        "Informational": "#94a3b8",
    }
    return count_pie_segments(
        severity,
        SEVERITY_ORDER,
        colors,
        lambda key: f"/findings?severity={quote_plus(key)}",
    )


def count_pie_style(counts: dict[str, int], order: list[str], colors: dict[str, str]) -> str:
    total = max(1, sum(counts.values()))
    cursor = 0.0
    stops: list[str] = []
    for key in order:
        value = counts.get(key, 0)
        if value <= 0:
            continue
        start = cursor
        cursor += (value / total) * 100
        color = colors.get(key, "#64748b")
        stops.append(f"{color} {start:.2f}% {cursor:.2f}%")
    if not stops:
        stops.append("#334155 0% 100%")
    return "background: conic-gradient(" + ", ".join(stops) + ");"


def findings_as_rows(findings: list[Finding]) -> list[dict[str, str | int | None]]:
    rows = []
    for f in findings:
        rows.append({
            "finding_id": f.id,
            "asset": f.asset.name if f.asset else "-",
            "environment": f.asset.environment if f.asset else "-",
            "scanner": f.scanner,
            "type": f.finding_type,
            "severity": f.severity_normalized,
            "risk_score": f.risk_score,
            "title": f.title,
            "cve": f.cve,
            "cwe": f.cwe,
            "package": f.package_name,
            "installed_version": f.installed_version,
            "fixed_version": f.fixed_version,
            "affected_component": f.affected_component,
            "status": f.status,
            "iris_alert_id": f.iris_alert_id,
            "recommendation": f.recommendation,
        })
    return rows


def export_findings_csv(findings: list[Finding]) -> str:
    rows = findings_as_rows(findings)
    output = io.StringIO()
    if not rows:
        output.write("finding_id,asset,severity,risk_score,title,status\n")
        return output.getvalue()
    writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def export_findings_xlsx(findings: list[Finding]) -> bytes:
    rows = findings_as_rows(findings)
    wb = Workbook()
    ws = wb.active
    ws.title = "Findings"
    headers = list(rows[0].keys()) if rows else ["finding_id", "asset", "severity", "risk_score", "title", "status"]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="1F2937")
        cell.alignment = Alignment(horizontal="center")
    for row in rows:
        ws.append([row.get(h) for h in headers])
    for column_cells in ws.columns:
        max_length = max(len(str(cell.value or "")) for cell in column_cells)
        ws.column_dimensions[column_cells[0].column_letter].width = min(max(max_length + 2, 12), 55)
    bio = io.BytesIO()
    wb.save(bio)
    return bio.getvalue()


def executive_markdown_report(summary: dict) -> str:
    sev = summary["severity"]
    status = summary["status"]
    lines = [
        "# SATRIA Vulnerability Summary Report",
        "",
        f"Generated at: {summary['generated_at']}",
        "",
        "## Executive Summary",
        "",
        f"- Assets monitored: {summary['assets']}",
        f"- Total scan jobs: {summary['scans']}",
        f"- Completed scans: {summary['completed_scans']}",
        f"- Failed scans: {summary['failed_scans']}",
        f"- Total findings: {summary['findings']}",
        f"- Open/actionable findings: {summary['open_findings']}",
        f"- Critical + High findings: {summary['critical_high']}",
        "",
        "## Severity Breakdown",
        "",
    ]
    for key, value in sev.items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Status Breakdown", ""])
    for key, value in status.items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Top Risk Assets", ""])
    for item in summary["top_assets"]:
        lines.append(f"- {item['name']}: {item['total']} finding(s), max risk {item['max_risk']}")
    lines.extend(["", "## Recommended Follow-up", "", "- Validate Critical/High findings and send confirmed items to DFIR-IRIS as alerts/cases.", "- Assign remediation owners and perform retest after fixes.", "- Keep raw scanner reports as evidence for audit and closure."])
    return "\n".join(lines) + "\n"
