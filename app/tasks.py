from datetime import datetime
from celery import Celery
from sqlalchemy.exc import IntegrityError
from .config import get_settings
from .database import SessionLocal
from .models import AuditLog, Finding, ScanJob
from .scanner_runner import run_scanner, scanners_for_profile
from .normalizers import normalize_report

settings = get_settings()
celery_app = Celery('satria', broker=settings.celery_broker_url, backend=settings.celery_result_backend)

@celery_app.task(name='run_scan_job')
def run_scan_job(scan_job_id: int) -> dict:
    db = SessionLocal()
    try:
        job = db.get(ScanJob, scan_job_id)
        if not job:
            return {'status': 'not_found', 'scan_job_id': scan_job_id}
        asset = job.asset
        job.status = 'running'
        job.started_at = datetime.utcnow()
        db.commit()

        all_messages = []
        total_findings = 0
        scanners = scanners_for_profile(job.profile)
        for scanner in scanners:
            # Update current scanner label for simple UI visibility.
            job.scanner = '+'.join(scanners)
            db.commit()
            report_path, payload, msg = run_scanner(scanner, asset.asset_type, asset.target, settings.report_dir, job.id, job.profile)
            all_messages.append(f'{scanner}: {msg}')
            job.raw_report_path = str(report_path)
            db.commit()

            normalized = normalize_report(scanner, payload, asset.id, asset.criticality)
            for item in normalized:
                existing = db.query(Finding).filter(Finding.dedup_key == item['dedup_key']).one_or_none()
                if existing:
                    existing.last_seen_at = datetime.utcnow()
                    existing.scan_job_id = job.id
                    existing.status = 'Open' if existing.status in {'Resolved', 'Closed'} else existing.status
                    existing.risk_score = item['risk_score']
                    continue
                finding = Finding(
                    asset_id=asset.id,
                    scan_job_id=job.id,
                    scanner=scanner,
                    finding_type=item.get('finding_type', 'unknown'),
                    title=item.get('title', 'Untitled finding'),
                    description=item.get('description'),
                    severity_original=item.get('severity_original', 'UNKNOWN'),
                    severity_normalized=item.get('severity_normalized', 'Informational'),
                    cve=item.get('cve'),
                    cwe=item.get('cwe'),
                    cvss_score=item.get('cvss_score'),
                    package_name=item.get('package_name'),
                    installed_version=item.get('installed_version'),
                    fixed_version=item.get('fixed_version'),
                    affected_component=item.get('affected_component'),
                    evidence=item.get('evidence'),
                    recommendation=item.get('recommendation'),
                    risk_score=item.get('risk_score', 0),
                    status='Open',
                    dedup_key=item['dedup_key'],
                )
                db.add(finding)
                try:
                    db.flush()
                    total_findings += 1
                except IntegrityError:
                    db.rollback()
            db.commit()

        job.status = 'completed'
        job.completed_at = datetime.utcnow()
        job.message = '\n'.join(all_messages) + f'\nnew_findings={total_findings}'
        db.add(AuditLog(action='scan_completed', object_type='scan_job', object_id=str(job.id), detail=job.message))
        db.commit()
        return {'status': 'completed', 'scan_job_id': job.id, 'new_findings': total_findings}
    except Exception as exc:
        db.rollback()
        job = db.get(ScanJob, scan_job_id)
        if job:
            job.status = 'failed'
            job.completed_at = datetime.utcnow()
            job.message = str(exc)
            db.commit()
        return {'status': 'failed', 'scan_job_id': scan_job_id, 'error': str(exc)}
    finally:
        db.close()
