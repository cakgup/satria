"""Local smoke test for SATRIA MVP.

This test does not need Docker, PostgreSQL, Redis, Trivy, Syft, Grype, ZAP,
OpenVAS, or DFIR-IRIS. It runs the FastAPI app with SQLite and demo-mode
scanner payloads, then verifies the core workflow:
asset -> scan job -> normalized findings -> UI pages -> IRIS stub.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

# Must be set before importing SATRIA modules, because settings/database are
# initialized at import time.
os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/satria_smoke_test.db")
os.environ.setdefault("REPORT_DIR", "/tmp/satria_smoke_reports")
os.environ.setdefault("SATRIA_DEMO_MODE", "true")
os.environ.setdefault("CELERY_BROKER_URL", "memory://")
os.environ.setdefault("CELERY_RESULT_BACKEND", "cache+memory://")
os.environ["IRIS_URL"] = ""
os.environ["IRIS_API_KEY"] = ""

def sqlite_path_from_url(url: str) -> Path | None:
    if not url.startswith("sqlite:///"):
        return None
    raw = url.replace("sqlite:///", "", 1)
    if raw.startswith("/"):
        return Path(raw)
    return Path(raw)


DB_PATH = sqlite_path_from_url(os.environ["DATABASE_URL"])
REPORT_DIR = Path(os.environ["REPORT_DIR"])
if DB_PATH is not None:
    DB_PATH.unlink(missing_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)
for old_report in REPORT_DIR.glob("*.json"):
    old_report.unlink()

from fastapi.testclient import TestClient  # noqa: E402

import app.main as main  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.models import Asset, Finding, ScanJob, TicketCase, TicketEvidence, TicketTask  # noqa: E402
from app.tasks import run_scan_job  # noqa: E402


def run_sync_delay(scan_job_id: int):
    """Replace Celery async dispatch with direct execution for local smoke test."""
    return run_scan_job(scan_job_id)


main.run_scan_job.delay = run_sync_delay
init_db()

with TestClient(main.app) as client:
    checks: list[str] = []

    health = client.get("/health")
    assert health.status_code == 200, health.text
    checks.append("health endpoint OK")

    asset_payload = {
        "name": "Smoke Test SAKTI API Image",
        "asset_type": "container_image",
        "target": "registry.local/sakti-api:latest",
        "environment": "development",
        "criticality": "critical",
        "owner": "SITP",
        "technical_pic": "DevSecOps",
    }
    asset_resp = client.post("/api/assets", json=asset_payload)
    assert asset_resp.status_code == 200, asset_resp.text
    asset_id = asset_resp.json()["id"]
    checks.append("asset API OK")

    scan_resp = client.post("/api/scans", json={"asset_id": asset_id, "profile": "full_container"})
    assert scan_resp.status_code == 200, scan_resp.text
    checks.append("scan API OK")

    findings_resp = client.get("/api/findings")
    assert findings_resp.status_code == 200, findings_resp.text
    findings = findings_resp.json()
    assert len(findings) >= 3, findings
    assert any(f["scanner"] == "trivy" for f in findings), findings
    assert any(f["scanner"] == "syft" for f in findings), findings
    assert any(f["scanner"] == "grype" for f in findings), findings
    checks.append("finding normalization OK")

    for path in ["/", "/assets", "/scan/new", "/scans", "/findings", "/tickets", "/vulnerability-summary"]:
        page = client.get(path)
        assert page.status_code == 200, f"{path}: {page.status_code}"
    checks.append("HTML dashboard pages OK")

    with SessionLocal() as db:
        db_counts = {
            "assets": db.query(Asset).count(),
            "scans": db.query(ScanJob).count(),
            "findings": db.query(Finding).count(),
        }
        assert db_counts["assets"] == 1, db_counts
        assert db_counts["scans"] == 1, db_counts
        assert db_counts["findings"] >= 3, db_counts
        finding = db.query(Finding).order_by(Finding.risk_score.desc()).first()
        assert finding is not None
        iris_resp = client.post(f"/findings/{finding.id}/send-to-iris", follow_redirects=False)
        assert iris_resp.status_code == 303, iris_resp.text
        db.refresh(finding)
        ticket = db.query(TicketCase).filter(TicketCase.finding_id == finding.id).first()
        assert ticket is not None
        assert ticket.remote_case_id and ticket.remote_case_id.startswith("IRIS-STUB-CASE-"), ticket.remote_case_id
        assert db.query(TicketTask).filter(TicketTask.ticket_case_id == ticket.id).count() >= 1
        assert db.query(TicketEvidence).filter(TicketEvidence.ticket_case_id == ticket.id).count() >= 1
        detail = client.get(f"/tickets/{ticket.id}")
        assert detail.status_code == 200, detail.text
    checks.append("DFIR-IRIS-aligned local ticket workflow OK")

reports = sorted(REPORT_DIR.glob("*.json"))
assert len(reports) >= 3, reports
for report in reports:
    json.loads(report.read_text(encoding="utf-8"))
checks.append("raw report JSON files OK")

print("SATRIA smoke test PASSED")
for item in checks:
    print(f"- {item}")
print(f"- reports generated: {len(reports)}")
