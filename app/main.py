from datetime import datetime
from pathlib import Path
from urllib.parse import quote_plus
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from .database import get_db, init_db
from .config import get_settings
from .models import Asset, AuditLog, Finding, ScanJob, TicketCase
from .schemas import AssetCreate, AssetOut, FindingOut, ScanCreate, ScanOut
from .scanner_runner import SUPPORTED_PROFILES, scanners_for_profile
from .tasks import run_scan_job
from .iris import delete_remote_ticket_case, get_remote_case_bundle, list_remote_cases, refresh_ticket_case_from_iris, send_finding_to_iris, sync_ticket_case
from .reporting import active_findings_query, count_pie_segments, get_summary, severity_pie_segments, severity_pie_style, export_findings_csv, export_findings_xlsx, executive_markdown_report
from .soc import MANUAL_PLAYBOOKS, SOC_DEMO_USERS, SOC_SOP, classification_label_for_case, default_soc_id_for_case, playbook_choices, tags_for_case
from .ticketing import add_ticket_activity, add_ticket_evidence, add_ticket_task, create_manual_case_from_playbook, seed_demo_manual_cases, update_ticket_case

app = FastAPI(title='SATRIA', version='0.1.0-mvp')
app.mount('/static', StaticFiles(directory='app/static'), name='static')
templates = Jinja2Templates(directory='app/templates')

PUBLIC_PATH_PREFIXES = (
    '/static',
    '/login',
    '/health',
    '/docs',
    '/openapi.json',
    '/redoc',
    '/favicon.ico',
)

ASSET_TYPE_ORDER = [
    'container_image',
    'web_application',
    'server_ip',
    'source_repository',
    'filesystem',
    'api_endpoint',
]

ASSET_TYPE_META = {
    'container_image': {
        'label': 'Container image',
        'target_example': 'registry.internal/sakti-api:2026.07.01',
        'hero': 'Panduan operasional pendaftaran dan pemindaian artefak container image.',
        'summary': 'Gunakan mode ini untuk artefak image sebelum deploy. Container tidak harus berjalan, tetapi image harus tersedia atau dapat dipull dari server SATRIA.',
        'cards': [
            {'title': 'Target umum', 'value': 'repo/image:tag', 'caption': 'Contoh: registry.internal/app:2026.07.01'},
            {'title': 'Profile utama', 'value': 'quick_container', 'caption': 'Dapat dilanjutkan ke full_container atau sbom_scan'},
        ],
        'sections': [
            {'title': 'Cara operasional yang benar untuk tim', 'items': [
                'Pastikan image yang akan discan dapat diakses dari server SATRIA, baik melalui pull langsung, registry internal, maupun hasil load dari archive.',
                'Daftarkan aset di menu Assets dengan jenis target Container image.',
                'Isi Target dengan nama image beserta tag versi yang benar.',
                'Simpan aset, lalu buat scan job dengan profile container seperti quick_container, full_container, atau sbom_scan.',
            ]},
            {'title': 'Opsi 1: paling mudah di server SATRIA', 'items': [
                'Jalankan docker pull repo/image:tag di server SATRIA.',
                'Tambahkan aset dengan jenis target Container image.',
                'Isi Target = repo/image:tag.',
                'Simpan aset dan jalankan scan profile container.',
            ]},
            {'title': 'Opsi 2: image dibuat di server build lain', 'items': [
                'Push image ke registry internal, misalnya registry.internal/app:tag.',
                'Dari server SATRIA jalankan docker pull registry.internal/app:tag.',
                'Daftarkan aset SATRIA dengan target registry.internal/app:tag.',
                'Jalankan scan container dari SATRIA.',
            ]},
            {'title': 'Opsi 3: belum ada registry', 'items': [
                'Dari server asal jalankan docker save untuk membuat archive image.',
                'Pindahkan archive tersebut ke server SATRIA.',
                'Di server SATRIA jalankan docker load.',
                'Scan nama image hasil docker load tersebut dari SATRIA.',
            ]},
            {'title': 'Yang perlu dipahami', 'items': [
                'Container image berbeda dengan Web application maupun Server / IP.',
                'Jika target yang diuji adalah aplikasi aktif di URL, gunakan mode web seperti web_baseline atau web_full.',
                'Container tidak perlu sedang running; yang penting image tersedia di host SATRIA atau dapat dipull dari sana.',
            ]},
        ],
    },
    'web_application': {
        'label': 'Web application',
        'target_example': 'https://portal.example.go.id',
        'hero': 'Panduan operasional pendaftaran dan pemindaian aplikasi web yang aktif.',
        'summary': 'Gunakan mode ini bila target utama adalah aplikasi web yang sedang hidup dan dapat diakses melalui URL.',
        'cards': [
            {'title': 'Target umum', 'value': 'https://...', 'caption': 'Gunakan URL aktif yang benar-benar dapat diakses'},
            {'title': 'Profile utama', 'value': 'web_baseline', 'caption': 'Dapat dilanjutkan ke web_full'},
        ],
        'sections': [
            {'title': 'Langkah operasional yang dianjurkan', 'items': [
                'Pastikan URL aplikasi benar dan sedang aktif.',
                'Daftarkan aset dengan jenis target Web application.',
                'Isi Target dengan URL utama yang akan diuji.',
                'Simpan aset lalu jalankan scan dengan profile web seperti web_baseline atau web_full.',
            ]},
            {'title': 'Yang perlu dipahami', 'items': [
                'Mode ini dipakai untuk aplikasi yang hidup, bukan untuk artefak image sebelum deploy.',
                'Temuan biasanya berkaitan dengan header, autentikasi, route, input handling, dan exposure aplikasi.',
            ]},
        ],
    },
    'server_ip': {
        'label': 'Server / IP',
        'target_example': '10.216.208.249',
        'hero': 'Panduan operasional pendaftaran target host, server, atau alamat IP.',
        'summary': 'Gunakan mode ini untuk pemeriksaan infrastruktur dan layanan host yang berada dalam ruang lingkup scanning.',
        'cards': [
            {'title': 'Target umum', 'value': 'IP / hostname', 'caption': 'Contoh: 10.216.208.249'},
            {'title': 'Catatan', 'value': 'Allowlist', 'caption': 'Pastikan target sesuai kebijakan scanning'},
        ],
        'sections': [
            {'title': 'Langkah operasional yang dianjurkan', 'items': [
                'Pastikan IP atau hostname berada dalam allowlist dan memang boleh diuji.',
                'Daftarkan aset dengan jenis target Server / IP.',
                'Isi Target dengan alamat host yang tepat.',
                'Simpan aset lalu jalankan profile infrastruktur yang sesuai kebijakan lingkungan.',
            ]},
            {'title': 'Yang perlu dipahami', 'items': [
                'Mode ini berbeda dari aplikasi web dan berbeda dari artefak container image.',
                'Gunakan hanya untuk target host yang sudah disetujui secara operasional.',
            ]},
        ],
    },
    'source_repository': {
        'label': 'Source repository',
        'target_example': 'https://git.internal/example/app.git',
        'hero': 'Panduan operasional intake aset dari source code repository.',
        'summary': 'Gunakan mode ini sebelum artefak build atau container image dibuat, terutama saat fokus ada pada source code dan dependency.',
        'cards': [
            {'title': 'Target umum', 'value': 'URL / path repo', 'caption': 'Gunakan referensi repository yang konsisten'},
            {'title': 'Fokus', 'value': 'Code-level', 'caption': 'Cocok untuk dependency dan source structure'},
        ],
        'sections': [
            {'title': 'Langkah operasional yang dianjurkan', 'items': [
                'Pastikan referensi repo atau path clone yang dipakai adalah yang benar.',
                'Daftarkan aset dengan jenis target Source repository.',
                'Isi Target dengan URL atau path repository yang sesuai proses internal.',
                'Gunakan mode ini bila fokusnya dependency, source structure, atau artefak code-level lain.',
            ]},
        ],
    },
    'filesystem': {
        'label': 'Filesystem',
        'target_example': '/opt/releases/sakti-api',
        'hero': 'Panduan operasional pendaftaran target berupa folder atau bundle file di host SATRIA.',
        'summary': 'Gunakan mode ini saat target tersedia sebagai direktori kerja, bundle release, atau hasil ekstraksi yang sudah berada di server SATRIA.',
        'cards': [
            {'title': 'Target umum', 'value': '/path/to/data', 'caption': 'Gunakan path lengkap yang valid di host'},
            {'title': 'Fokus', 'value': 'Bundle lokal', 'caption': 'Cocok untuk direktori atau hasil ekstraksi'},
        ],
        'sections': [
            {'title': 'Langkah operasional yang dianjurkan', 'items': [
                'Pastikan path yang akan digunakan benar-benar ada di server SATRIA.',
                'Daftarkan aset dengan jenis target Filesystem.',
                'Isi Target dengan path lengkap yang ingin discan.',
                'Mode ini cocok untuk bundle release, hasil ekstraksi image, atau direktori kerja tertentu.',
            ]},
        ],
    },
    'api_endpoint': {
        'label': 'API endpoint',
        'target_example': 'https://api.example.go.id/v1',
        'hero': 'Panduan operasional pendaftaran target berupa endpoint API yang aktif.',
        'summary': 'Gunakan mode ini saat fokus pengujian ada pada permukaan layanan API yang berjalan dan perlu dipantau dari sisi aplikasi.',
        'cards': [
            {'title': 'Target umum', 'value': 'https://api/...', 'caption': 'Gunakan base URL endpoint utama'},
            {'title': 'Fokus', 'value': 'Surface API', 'caption': 'Membedakan target API dari image atau host'},
        ],
        'sections': [
            {'title': 'Langkah operasional yang dianjurkan', 'items': [
                'Pastikan base URL API yang dimasukkan benar dan dapat diakses.',
                'Daftarkan aset dengan jenis target API endpoint.',
                'Isi Target dengan endpoint utama atau base path API.',
                'Gunakan mode ini untuk membedakan pengujian API aktif dari image container atau host server.',
            ]},
        ],
    },
}


def _safe_next_path(next_path: str | None) -> str:
    if not next_path or not next_path.startswith('/'):
        return '/'
    if next_path.startswith('//'):
        return '/'
    return next_path


@app.middleware('http')
async def require_login(request: Request, call_next):
    request.state.current_user = request.cookies.get('satria_user')
    path = request.url.path
    if any(path.startswith(prefix) for prefix in PUBLIC_PATH_PREFIXES):
        return await call_next(request)

    if request.state.current_user:
        return await call_next(request)

    destination = quote_plus(path)
    if request.url.query:
        destination = quote_plus(f'{path}?{request.url.query}')
    return RedirectResponse(url=f'/login?next={destination}', status_code=303)


def _scan_mode(scan: ScanJob) -> tuple[str, str]:
    message = (scan.message or '').lower()
    if 'sample payload generated' in message:
        return 'Simulated', 'mode-demo'
    if 'allowlist' in message:
        return 'Blocked', 'mode-failed'
    if 'openvas connector' in message or 'greenbone' in message:
        return 'Connector', 'mode-failed'
    if 'active scan disabled' in message:
        return 'Policy', 'mode-failed'
    if scan.status == 'completed':
        return 'Real', 'mode-real'
    if scan.status == 'running':
        return 'Running', ''
    if scan.status == 'queued':
        return 'Queued', ''
    return 'Failed', 'mode-failed'


def _scan_message_summary(scan: ScanJob) -> str:
    message = (scan.message or '').strip()
    if not message:
        return '-'

    if scan.scanner == 'openvas':
        first_line = next((line.strip() for line in message.splitlines() if line.strip()), '')
        if first_line:
            summary = first_line
            if ' report_id=' in summary:
                summary = summary.split(' report_id=', 1)[0]
            return summary

    if scan.scanner == 'zap':
        lower = message.lower()
        if 'total of ' in lower and ' urls' in lower:
            start = lower.find('total of ')
            end = lower.find(' urls', start)
            total = message[start + len('total of '):end].strip()
            return f'zap: total_urls={total}'
        first_line = next((line.strip() for line in message.splitlines() if line.strip()), '')
        return (first_line[:120] + '...') if len(first_line) > 120 else first_line

    first_line = next((line.strip() for line in message.splitlines() if line.strip()), '')
    return (first_line[:120] + '...') if len(first_line) > 120 else first_line


def _scan_row(scan: ScanJob) -> dict:
    mode_label, mode_class = _scan_mode(scan)
    has_remote_cleanup = any(
        finding.ticket_case and (finding.ticket_case.remote_case_id or finding.ticket_case.remote_alert_id)
        for finding in scan.findings
    )
    return {
        'id': scan.id,
        'asset_id': scan.asset_id,
        'asset_name': scan.asset.name if scan.asset else '-',
        'profile': scan.profile,
        'scanner': scan.scanner,
        'status': scan.status,
        'mode_label': mode_label,
        'mode_class': mode_class,
        'report_path': scan.raw_report_path or '-',
        'message': scan.message or '-',
        'message_summary': _scan_message_summary(scan),
        'created_at': scan.created_at,
        'can_delete': scan.status != 'running',
        'can_retry': bool(scan.asset_id and scan.profile and scan.status != 'running'),
        'has_remote_cleanup': has_remote_cleanup,
        'findings_count': len(scan.findings),
    }


def _remove_report_file(raw_report_path: str | None):
    if not raw_report_path:
        return
    report_path = Path(raw_report_path)
    if report_path.exists() and report_path.is_file():
        report_path.unlink(missing_ok=True)


def _delete_scan_payload(db: Session, scan: ScanJob) -> dict[str, int]:
    finding_ids = [item.id for item in db.query(Finding.id).filter(Finding.scan_job_id == scan.id).all()]
    tickets_deleted = 0
    findings_deleted = 0

    for finding_id in finding_ids:
        ticket = db.query(TicketCase).filter(TicketCase.finding_id == finding_id).first()
        if ticket:
            db.delete(ticket)
            tickets_deleted += 1
        finding = db.get(Finding, finding_id)
        if finding:
            db.delete(finding)
            findings_deleted += 1

    _remove_report_file(scan.raw_report_path)
    db.delete(scan)
    return {
        'tickets_deleted': tickets_deleted,
        'findings_deleted': findings_deleted,
    }


def _remote_tickets_for_scan(scan: ScanJob) -> list[TicketCase]:
    tickets: list[TicketCase] = []
    for finding in scan.findings:
        ticket = finding.ticket_case
        if ticket and (ticket.remote_case_id or ticket.remote_alert_id):
            tickets.append(ticket)
    return tickets


def _remote_tickets_for_asset(asset: Asset) -> list[TicketCase]:
    tickets: list[TicketCase] = []
    seen: set[int] = set()
    for ticket in asset.ticket_cases:
        if ticket.id in seen:
            continue
        if ticket.remote_case_id or ticket.remote_alert_id:
            tickets.append(ticket)
            seen.add(ticket.id)
    return tickets


def _delete_asset_payload(db: Session, asset: Asset) -> dict[str, int]:
    scans_deleted = 0
    findings_deleted = 0
    tickets_deleted = 0

    for ticket in list(asset.ticket_cases):
        db.delete(ticket)
        tickets_deleted += 1

    for finding in list(asset.findings):
        db.delete(finding)
        findings_deleted += 1

    for scan in list(asset.scans):
        _remove_report_file(scan.raw_report_path)
        db.delete(scan)
        scans_deleted += 1

    db.delete(asset)
    return {
        'scans_deleted': scans_deleted,
        'findings_deleted': findings_deleted,
        'tickets_deleted': tickets_deleted,
    }

@app.on_event('startup')
def on_startup():
    init_db()

@app.get('/health')
def health():
    return {'status': 'ok', 'app': 'SATRIA'}


@app.get('/login', response_class=HTMLResponse)
def login_page(request: Request, next: str = '/'):
    if request.cookies.get('satria_user'):
        return RedirectResponse(url=_safe_next_path(next), status_code=303)
    return templates.TemplateResponse('login.html', {
        'request': request,
        'next_url': _safe_next_path(next),
        'error': None,
    })


@app.post('/login', response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form('top-management'),
    next_url: str = Form('/'),
):
    cleaned_username = (username or 'top-management').strip() or 'top-management'
    if not cleaned_username:
        return templates.TemplateResponse('login.html', {
            'request': request,
            'next_url': _safe_next_path(next_url),
            'error': 'Username wajib diisi.',
        }, status_code=400)

    response = RedirectResponse(url=_safe_next_path(next_url), status_code=303)
    response.set_cookie(
        key='satria_user',
        value=cleaned_username,
        httponly=True,
        samesite='lax',
        secure=False,
        max_age=60 * 60 * 12,
    )
    return response


@app.post('/logout')
def logout(request: Request):
    response = RedirectResponse(url='/login', status_code=303)
    response.delete_cookie('satria_user')
    return response

@app.get('/', response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    summary = get_summary(db)
    counts = {
        'assets': summary['assets'],
        'scans': summary['scans'],
        'findings': summary['findings'],
        'open': summary['open_findings'],
    }
    latest_findings = active_findings_query(db).order_by(Finding.risk_score.desc(), Finding.id.desc()).limit(10).all()
    latest_scans = db.query(ScanJob).filter(ScanJob.is_visible == True).order_by(ScanJob.id.desc()).limit(10).all()  # noqa: E712
    return templates.TemplateResponse('dashboard.html', {
        'request': request,
        'counts': counts,
        'severity': summary['severity'],
        'summary': summary,
        'pie_style': severity_pie_style(summary['severity']),
        'pie_segments': severity_pie_segments(summary['severity']),
        'latest_findings': latest_findings,
        'latest_scans': latest_scans,
    })

@app.get('/vulnerability-summary', response_class=HTMLResponse)
def vulnerability_summary(request: Request, db: Session = Depends(get_db)):
    summary = get_summary(db)
    return templates.TemplateResponse('vulnerability_summary.html', {
        'request': request,
        'summary': summary,
        'pie_style': severity_pie_style(summary['severity']),
        'severity_pie_segments': severity_pie_segments(summary['severity']),
        'status_pie_segments': count_pie_segments(
            summary['status'],
            list(summary['status'].keys()),
            {
                'Open': '#2563eb',
                'Assigned': '#7c3aed',
                'In Progress': '#f97316',
                'Remediated': '#14b8a6',
                'Retest': '#facc15',
                'Closed': '#22c55e',
                'False Positive': '#94a3b8',
                'Accepted Risk': '#64748b',
            },
            lambda key: f'/findings?status={quote_plus(key)}',
        ),
        'scanner_pie_segments': count_pie_segments(
            summary['scanner'],
            list(summary['scanner'].keys()),
            {
                'trivy': '#2563eb',
                'syft': '#14b8a6',
                'grype': '#f97316',
                'zap': '#7c3aed',
                'openvas': '#ef4444',
            },
            lambda key: f'/findings?scanner={quote_plus(key)}',
        ),
    })

@app.get('/assets', response_class=HTMLResponse)
def assets_page(
    request: Request,
    cleanup_status: str | None = None,
    cleanup_message: str | None = None,
    db: Session = Depends(get_db),
):
    assets = db.query(Asset).filter(Asset.is_active == True).order_by(Asset.id.desc()).all()  # noqa: E712
    return templates.TemplateResponse('assets.html', {
        'request': request,
        'assets': assets,
        'summary': get_summary(db),
        'cleanup_status': cleanup_status,
        'cleanup_message': cleanup_message,
    })


@app.get('/asset-sop', response_class=HTMLResponse)
def asset_sop_page(request: Request, asset_type: str = 'container_image'):
    selected_asset_type = asset_type if asset_type in ASSET_TYPE_META else 'container_image'
    return templates.TemplateResponse('asset_sop.html', {
        'request': request,
        'asset_type_order': ASSET_TYPE_ORDER,
        'asset_type_meta': ASSET_TYPE_META,
        'selected_asset_type': selected_asset_type,
        'selected_guide': ASSET_TYPE_META[selected_asset_type],
    })

@app.post('/assets')
def create_asset_form(
    name: str = Form(...),
    asset_type: str = Form(...),
    target: str = Form(...),
    environment: str = Form('development'),
    criticality: str = Form('medium'),
    owner: str = Form(''),
    technical_pic: str = Form(''),
    db: Session = Depends(get_db),
):
    asset = Asset(
        name=name,
        asset_type=asset_type,
        target=target,
        environment=environment,
        criticality=criticality,
        owner=owner or None,
        technical_pic=technical_pic or None,
    )
    db.add(asset)
    db.add(AuditLog(action='asset_created', object_type='asset', detail=name))
    db.commit()
    return RedirectResponse('/assets', status_code=303)


@app.post('/assets/{asset_id}/delete')
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if not asset or not asset.is_active:
        raise HTTPException(status_code=404, detail='asset not found')
    remote_tickets = _remote_tickets_for_asset(asset)
    remote_messages: list[str] = []
    remote_deleted = 0
    remote_skipped = 0

    for ticket in remote_tickets:
        result = delete_remote_ticket_case(ticket)
        if result.get('ok'):
            if result.get('status') == 'skipped':
                remote_skipped += 1
            else:
                remote_deleted += 1
            continue
        remote_messages.append(str(result.get('message') or 'remote cleanup failed'))

    if remote_messages:
        detail = quote_plus('; '.join(remote_messages))
        return RedirectResponse(
            f'/assets?cleanup_status=remote-failed&cleanup_message={detail}',
            status_code=303,
        )

    counts = _delete_asset_payload(db, asset)
    db.add(AuditLog(
        action='asset_deleted',
        object_type='asset',
        object_id=str(asset_id),
        detail=(
            f"name={asset.name}; scans={counts['scans_deleted']}; findings={counts['findings_deleted']}; "
            f"tickets={counts['tickets_deleted']}; remote_deleted={remote_deleted}; remote_skipped={remote_skipped}"
        ),
    ))
    db.commit()
    return RedirectResponse('/assets', status_code=303)

@app.get('/scan/new', response_class=HTMLResponse)
def new_scan_page(request: Request, asset_id: int | None = None, db: Session = Depends(get_db)):
    assets = db.query(Asset).filter(Asset.is_active == True).order_by(Asset.name).all()  # noqa: E712
    profiles = list(SUPPORTED_PROFILES)
    selected_asset = next((asset for asset in assets if asset.id == asset_id), None)
    return templates.TemplateResponse('scan_new.html', {
        'request': request,
        'assets': assets,
        'profiles': sorted(profiles),
        'selected_asset_id': selected_asset.id if selected_asset else None,
    })

@app.post('/scan')
def create_scan_form(asset_id: int = Form(...), profile: str = Form(...), db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail='asset not found')
    if profile not in SUPPORTED_PROFILES:
        raise HTTPException(status_code=400, detail='unsupported scan profile')
    job = ScanJob(asset_id=asset.id, profile=profile, scanner='+'.join(scanners_for_profile(profile)), status='queued')
    db.add(job)
    db.add(AuditLog(action='scan_created', object_type='scan_job', detail=f'{asset.name}/{profile}'))
    db.commit()
    db.refresh(job)
    run_scan_job.delay(job.id)
    return RedirectResponse('/scans', status_code=303)

@app.get('/scans', response_class=HTMLResponse)
def scans_page(
    request: Request,
    db: Session = Depends(get_db),
    status: str | None = None,
    profile: str | None = None,
):
    q = db.query(ScanJob).filter(ScanJob.is_visible == True)  # noqa: E712
    if status:
        q = q.filter(ScanJob.status == status)
    if profile:
        q = q.filter(ScanJob.profile == profile)
    scans = q.order_by(ScanJob.id.desc()).limit(60).all()
    scan_rows = [_scan_row(scan) for scan in scans]
    profiles = sorted({row[0] for row in db.query(ScanJob.profile).filter(ScanJob.is_visible == True).all() if row[0]})  # noqa: E712
    return templates.TemplateResponse('scans.html', {
        'request': request,
        'scans': scan_rows,
        'summary': get_summary(db),
        'status_filter': status,
        'profile_filter': profile,
        'profiles': profiles,
    })


@app.get('/scans/{scan_job_id}', response_class=HTMLResponse)
def scan_detail(
    request: Request,
    scan_job_id: int,
    cleanup_status: str | None = None,
    cleanup_message: str | None = None,
    db: Session = Depends(get_db),
):
    scan = db.get(ScanJob, scan_job_id)
    if not scan:
        raise HTTPException(status_code=404, detail='scan not found')
    findings = (
        db.query(Finding)
        .filter(Finding.scan_job_id == scan.id)
        .order_by(Finding.risk_score.desc(), Finding.id.desc())
        .all()
    )
    scan_row = _scan_row(scan)
    return templates.TemplateResponse('scan_detail.html', {
        'request': request,
        'scan': scan,
        'scan_row': scan_row,
        'findings': findings,
        'cleanup_status': cleanup_status,
        'cleanup_message': cleanup_message,
    })


@app.post('/scans/{scan_job_id}/delete')
def hide_scan_history(scan_job_id: int, next_url: str = Form('/scans'), db: Session = Depends(get_db)):
    scan = db.get(ScanJob, scan_job_id)
    if not scan:
        raise HTTPException(status_code=404, detail='scan not found')
    if scan.status == 'running':
        raise HTTPException(status_code=400, detail='running scan cannot be removed from history')
    counts = _delete_scan_payload(db, scan)
    db.add(AuditLog(
        action='scan_deleted',
        object_type='scan_job',
        object_id=str(scan_job_id),
        detail=f"profile={scan.profile}; findings={counts['findings_deleted']}; tickets={counts['tickets_deleted']}",
    ))
    db.commit()
    return RedirectResponse(next_url or '/scans', status_code=303)


@app.post('/scans/{scan_job_id}/delete-with-iris')
def delete_scan_with_remote_cleanup(
    scan_job_id: int,
    next_url: str = Form('/scans'),
    failure_url: str | None = Form(None),
    db: Session = Depends(get_db),
):
    scan = db.get(ScanJob, scan_job_id)
    if not scan:
        raise HTTPException(status_code=404, detail='scan not found')
    if scan.status == 'running':
        raise HTTPException(status_code=400, detail='running scan cannot be removed from history')

    related_remote_tickets = _remote_tickets_for_scan(scan)
    remote_deleted = 0
    remote_skipped = 0
    remote_messages: list[str] = []
    for ticket in related_remote_tickets:
        result = delete_remote_ticket_case(ticket)
        if result.get('ok'):
            if result.get('status') == 'skipped':
                remote_skipped += 1
            else:
                remote_deleted += 1
            continue
        remote_messages.append(str(result.get('message') or 'remote cleanup failed'))

    if remote_messages:
        fail_target = failure_url or f'/scans/{scan_job_id}'
        joiner = '&' if '?' in fail_target else '?'
        detail = quote_plus('; '.join(remote_messages))
        return RedirectResponse(
            f"{fail_target}{joiner}cleanup_status=remote-failed&cleanup_message={detail}",
            status_code=303,
        )

    counts = _delete_scan_payload(db, scan)
    db.add(AuditLog(
        action='scan_deleted_with_remote_cleanup',
        object_type='scan_job',
        object_id=str(scan_job_id),
        detail=(
            f"findings={counts['findings_deleted']}; tickets={counts['tickets_deleted']}; "
            f"remote_deleted={remote_deleted}; remote_skipped={remote_skipped}"
        ),
    ))
    db.commit()
    return RedirectResponse(next_url or '/scans', status_code=303)


@app.post('/scans/{scan_job_id}/rerun')
def rerun_scan(scan_job_id: int, next_url: str = Form('/scans'), db: Session = Depends(get_db)):
    scan = db.get(ScanJob, scan_job_id)
    if not scan:
        raise HTTPException(status_code=404, detail='scan not found')
    asset = db.get(Asset, scan.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail='asset not found')
    if scan.status == 'running':
        raise HTTPException(status_code=400, detail='running scan cannot be rerun')
    if scan.profile not in SUPPORTED_PROFILES:
        raise HTTPException(status_code=400, detail='unsupported scan profile')

    job = ScanJob(
        asset_id=asset.id,
        profile=scan.profile,
        scanner='+'.join(scanners_for_profile(scan.profile)),
        status='queued',
    )
    db.add(job)
    db.add(AuditLog(action='scan_rerun', object_type='scan_job', object_id=str(scan.id), detail=f'{asset.name}/{scan.profile}'))
    db.commit()
    db.refresh(job)
    run_scan_job.delay(job.id)
    return RedirectResponse(next_url or '/scans', status_code=303)


@app.post('/scans/archive-operational')
def archive_non_operational_scans(db: Session = Depends(get_db)):
    scans = db.query(ScanJob).filter(ScanJob.is_visible == True).all()  # noqa: E712
    hidden = 0
    for scan in scans:
        message = scan.message or ''
        should_hide = (
            scan.status == 'failed'
            or 'sample payload generated' in message
            or 'worker restarted during validation' in message
        )
        if not should_hide:
            continue
        if scan.raw_report_path:
            report_path = Path(scan.raw_report_path)
            if report_path.exists() and report_path.is_file():
                report_path.unlink(missing_ok=True)
        scan.raw_report_path = None
        scan.is_visible = False
        hidden += 1
    db.add(AuditLog(action='scan_history_archived', object_type='scan_job', detail=f'hidden={hidden}'))
    db.commit()
    return RedirectResponse('/scans', status_code=303)

@app.get('/findings', response_class=HTMLResponse)
def findings_page(
    request: Request,
    db: Session = Depends(get_db),
    severity: str | None = None,
    status: str | None = None,
    scanner: str | None = None,
    asset_id: int | None = None,
    scan_job_id: int | None = None,
):
    q = active_findings_query(db)
    asset_options_query = active_findings_query(db)
    if severity:
        q = q.filter(Finding.severity_normalized == severity)
        asset_options_query = asset_options_query.filter(Finding.severity_normalized == severity)
    if status:
        q = q.filter(Finding.status == status)
        asset_options_query = asset_options_query.filter(Finding.status == status)
    if scanner:
        q = q.filter(Finding.scanner == scanner)
        asset_options_query = asset_options_query.filter(Finding.scanner == scanner)
    if asset_id:
        q = q.filter(Finding.asset_id == asset_id)
    if scan_job_id:
        q = q.filter(Finding.scan_job_id == scan_job_id)
        asset_options_query = asset_options_query.filter(Finding.scan_job_id == scan_job_id)
    findings = (
        q.options(
            joinedload(Finding.asset),
            joinedload(Finding.ticket_case),
        )
        .order_by(Finding.risk_score.desc(), Finding.id.desc())
        .limit(300)
        .all()
    )
    asset_ids_subquery = asset_options_query.with_entities(Finding.asset_id.label('asset_id')).distinct().subquery()
    assets = (
        db.query(Asset)
        .join(asset_ids_subquery, Asset.id == asset_ids_subquery.c.asset_id)
        .filter(Asset.is_active == True)  # noqa: E712
        .order_by(Asset.name)
        .all()
    )
    selected_asset = next((asset for asset in assets if asset.id == asset_id), None) if asset_id else None
    selected_scan = db.get(ScanJob, scan_job_id) if scan_job_id else None
    active_filters: list[dict[str, str]] = []
    if scan_job_id:
        scan_label = f"Scan #{scan_job_id}"
        if selected_scan and selected_scan.asset:
            scan_label = f"Scan #{scan_job_id} - {selected_scan.asset.name}"
        active_filters.append({'label': 'Scan', 'value': scan_label})
    if severity:
        active_filters.append({'label': 'Severity', 'value': severity})
    if status:
        active_filters.append({'label': 'Status', 'value': status})
    if scanner:
        active_filters.append({'label': 'Scanner', 'value': scanner.upper()})
    if selected_asset:
        active_filters.append({'label': 'Aset', 'value': selected_asset.name})
    return templates.TemplateResponse('findings.html', {
        'request': request,
        'findings': findings,
        'summary': get_summary(db),
        'severity_filter': severity,
        'status_filter': status,
        'scanner_filter': scanner,
        'asset_filter': asset_id,
        'scan_job_filter': scan_job_id,
        'assets': assets,
        'scanners': ['trivy', 'syft', 'grype', 'zap', 'openvas'],
        'active_filters': active_filters,
    })


@app.get('/tickets', response_class=HTMLResponse)
def tickets_page(request: Request, db: Session = Depends(get_db), status: str | None = None, case_kind: str | None = None):
    q = db.query(TicketCase)
    if case_kind:
        q = q.filter(TicketCase.case_kind == case_kind)
    tickets = q.order_by(TicketCase.updated_at.desc(), TicketCase.id.desc()).limit(300).all()
    remote_cases = list_remote_cases()
    remote_case_map = {
        str(case.get('case_id')): case
        for case in remote_cases
        if case.get('case_id') is not None
    }
    monitored_tickets = []
    for ticket in tickets:
        remote = remote_case_map.get(str(ticket.remote_case_id))
        if remote_cases and ticket.remote_case_id and not remote:
            continue
        remote_state = (remote or {}).get('state_name')
        effective_status = remote_state or ticket.status
        if status and effective_status != status:
            continue
        monitored_tickets.append(ticket)
    return templates.TemplateResponse('tickets.html', {
        'request': request,
        'tickets': monitored_tickets,
        'ticket_views': {ticket.id: _ticket_case_view(ticket, remote_case_map.get(str(ticket.remote_case_id))) for ticket in monitored_tickets},
        'remote_case_map': remote_case_map,
        'iris_login_url': _iris_login_url(),
        'summary': get_summary(db),
        'status_filter': status,
        'case_kind_filter': case_kind,
        'playbook_choices': playbook_choices(),
    })


@app.get('/tickets/new', response_class=HTMLResponse)
def new_ticket_page(request: Request, db: Session = Depends(get_db)):
    assets = db.query(Asset).filter(Asset.is_active == True).order_by(Asset.name).all()  # noqa: E712
    return templates.TemplateResponse('ticket_new.html', {
        'request': request,
        'assets': assets,
        'playbooks': playbook_choices(),
        'demo_users': SOC_DEMO_USERS,
    })

@app.get('/findings/{finding_id}', response_class=HTMLResponse)
def finding_detail(request: Request, finding_id: int, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail='finding not found')
    return templates.TemplateResponse('finding_detail.html', {'request': request, 'finding': finding})


@app.get('/tickets/{ticket_case_id}', response_class=HTMLResponse)
def ticket_detail(request: Request, ticket_case_id: int, db: Session = Depends(get_db)):
    ticket = db.get(TicketCase, ticket_case_id)
    if not ticket:
        raise HTTPException(status_code=404, detail='ticket not found')
    remote_bundle = get_remote_case_bundle(ticket)
    return templates.TemplateResponse('ticket_detail.html', {
        'request': request,
        'ticket': ticket,
        'ticket_view': _ticket_case_view(ticket, (remote_bundle or {}).get('summary')),
        'remote_bundle': remote_bundle,
        'iris_login_url': _iris_login_url(),
        'demo_users': SOC_DEMO_USERS,
    })


@app.get('/soc-sop', response_class=HTMLResponse)
def soc_sop_page(request: Request):
    return templates.TemplateResponse('soc_sop.html', {
        'request': request,
        'sop_sections': SOC_SOP,
        'playbooks': MANUAL_PLAYBOOKS,
        'demo_users': SOC_DEMO_USERS,
    })

@app.post('/findings/{finding_id}/status')
def update_finding_status(finding_id: int, status: str = Form(...), db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail='finding not found')
    finding.status = status
    if status in {'Closed', 'Resolved'}:
        finding.resolved_at = datetime.utcnow()
    db.add(AuditLog(action='finding_status_updated', object_type='finding', object_id=str(finding.id), detail=status))
    db.commit()
    return RedirectResponse(f'/findings/{finding.id}', status_code=303)

@app.post('/findings/{finding_id}/send-to-iris')
def send_to_iris(finding_id: int, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail='finding not found')
    iris_id = send_finding_to_iris(db, finding, finding.asset)
    db.add(AuditLog(action='finding_sent_to_iris', object_type='finding', object_id=str(finding.id), detail=iris_id))
    db.commit()
    return RedirectResponse(f'/findings/{finding.id}', status_code=303)


@app.post('/tickets/manual')
def create_manual_ticket_form(
    asset_id: int = Form(...),
    playbook_key: str = Form(...),
    reporter: str = Form(...),
    organization_unit: str = Form(...),
    db: Session = Depends(get_db),
):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail='asset not found')
    if playbook_key not in MANUAL_PLAYBOOKS:
        raise HTTPException(status_code=400, detail='invalid playbook')
    ticket = create_manual_case_from_playbook(
        db,
        asset=asset,
        playbook_key=playbook_key,
        reporter=reporter,
        organization_unit=organization_unit,
    )
    db.add(AuditLog(action='manual_ticket_created', object_type='ticket_case', object_id=str(ticket.id), detail=ticket.title))
    db.commit()
    return RedirectResponse(f'/tickets/{ticket.id}', status_code=303)


@app.post('/tickets/seed-demo')
def seed_demo_tickets(db: Session = Depends(get_db)):
    assets = {asset.name: asset for asset in db.query(Asset).all()}
    created = seed_demo_manual_cases(db, assets)
    db.add(AuditLog(action='demo_tickets_seeded', object_type='ticket_case', detail=f'created={len(created)}'))
    db.commit()
    return RedirectResponse('/tickets', status_code=303)


@app.post('/tickets/{ticket_case_id}/sync')
def sync_ticket(ticket_case_id: int, db: Session = Depends(get_db)):
    ticket = db.get(TicketCase, ticket_case_id)
    if not ticket:
        raise HTTPException(status_code=404, detail='ticket not found')
    sync_ticket_case(db, ticket)
    db.add(AuditLog(action='ticket_synced_to_iris', object_type='ticket_case', object_id=str(ticket.id), detail=ticket.last_sync_status))
    db.commit()
    return RedirectResponse(f'/tickets/{ticket.id}', status_code=303)


@app.post('/tickets/refresh')
def refresh_tickets_from_iris(db: Session = Depends(get_db)):
    tickets = db.query(TicketCase).filter(TicketCase.remote_case_id.is_not(None)).all()
    refreshed = 0
    for ticket in tickets:
        refresh_ticket_case_from_iris(ticket)
        refreshed += 1
    db.add(AuditLog(action='tickets_monitored_from_iris', object_type='ticket_case', detail=f'refreshed={refreshed}'))
    db.commit()
    return RedirectResponse('/tickets', status_code=303)


@app.post('/tickets/{ticket_case_id}/refresh')
def refresh_ticket_from_iris(ticket_case_id: int, db: Session = Depends(get_db)):
    ticket = db.get(TicketCase, ticket_case_id)
    if not ticket:
        raise HTTPException(status_code=404, detail='ticket not found')
    refresh_ticket_case_from_iris(ticket)
    db.add(AuditLog(action='ticket_monitored_from_iris', object_type='ticket_case', object_id=str(ticket.id), detail=ticket.remote_case_id or '-'))
    db.commit()
    return RedirectResponse(f'/tickets/{ticket.id}', status_code=303)


@app.post('/tickets/{ticket_case_id}/status')
def update_ticket_status(
    ticket_case_id: int,
    status: str = Form(...),
    current_role: str = Form(...),
    current_owner: str = Form(...),
    resolution_summary: str = Form(''),
    db: Session = Depends(get_db),
):
    ticket = db.get(TicketCase, ticket_case_id)
    if not ticket:
        raise HTTPException(status_code=404, detail='ticket not found')
    update_ticket_case(
        ticket,
        status=status,
        current_role=current_role,
        current_owner=current_owner,
        resolution_summary=resolution_summary or None,
    )
    add_ticket_activity(
        db,
        ticket,
        actor=current_owner,
        actor_role=current_role,
        activity_type='status-update',
        message=f"Case dipindahkan ke status {status} dengan owner {current_owner}.",
    )
    db.add(AuditLog(action='ticket_status_updated', object_type='ticket_case', object_id=str(ticket.id), detail=status))
    db.commit()
    return RedirectResponse(f'/tickets/{ticket.id}', status_code=303)


@app.post('/tickets/{ticket_case_id}/activity')
def add_ticket_activity_form(
    ticket_case_id: int,
    actor: str = Form(...),
    actor_role: str = Form(...),
    activity_type: str = Form(...),
    message: str = Form(...),
    db: Session = Depends(get_db),
):
    ticket = db.get(TicketCase, ticket_case_id)
    if not ticket:
        raise HTTPException(status_code=404, detail='ticket not found')
    add_ticket_activity(
        db,
        ticket,
        actor=actor,
        actor_role=actor_role,
        activity_type=activity_type,
        message=message,
    )
    db.add(AuditLog(action='ticket_activity_added', object_type='ticket_case', object_id=str(ticket.id), detail=activity_type))
    db.commit()
    return RedirectResponse(f'/tickets/{ticket.id}', status_code=303)


@app.post('/tickets/{ticket_case_id}/tasks')
def add_ticket_task_form(
    ticket_case_id: int,
    title: str = Form(...),
    description: str = Form(''),
    role: str = Form('L1'),
    assignee: str = Form(''),
    tags: str = Form(''),
    db: Session = Depends(get_db),
):
    ticket = db.get(TicketCase, ticket_case_id)
    if not ticket:
        raise HTTPException(status_code=404, detail='ticket not found')
    add_ticket_task(
        db,
        ticket,
        title=title,
        description=description or None,
        role=role or None,
        assignee=assignee or None,
        tags=[item.strip() for item in tags.split(',') if item.strip()],
        sync_mode=ticket.sync_mode,
        sort_order=len(ticket.tasks) * 10 + 10,
    )
    db.add(AuditLog(action='ticket_task_added', object_type='ticket_case', object_id=str(ticket.id), detail=title))
    db.commit()
    return RedirectResponse(f'/tickets/{ticket.id}', status_code=303)


@app.post('/tickets/{ticket_case_id}/evidences')
def add_ticket_evidence_form(
    ticket_case_id: int,
    filename: str = Form(...),
    description: str = Form(''),
    source_path: str = Form(''),
    db: Session = Depends(get_db),
):
    ticket = db.get(TicketCase, ticket_case_id)
    if not ticket:
        raise HTTPException(status_code=404, detail='ticket not found')
    add_ticket_evidence(
        db,
        ticket,
        filename=filename,
        description=description or None,
        source_path=source_path or None,
        sync_mode=ticket.sync_mode,
    )
    db.add(AuditLog(action='ticket_evidence_added', object_type='ticket_case', object_id=str(ticket.id), detail=filename))
    db.commit()
    return RedirectResponse(f'/tickets/{ticket.id}', status_code=303)

@app.post('/ticketing/send-critical-high-to-iris')
def send_critical_high_to_iris(db: Session = Depends(get_db)):
    findings = active_findings_query(db).filter(
        Finding.severity_normalized.in_(['Critical', 'High']),
        Finding.status.notin_(['Closed', 'False Positive', 'Accepted Risk'])
    ).order_by(Finding.risk_score.desc()).limit(100).all()
    sent = 0
    for finding in findings:
        if not finding.ticket_case:
            send_finding_to_iris(db, finding, finding.asset)
            sent += 1
    db.add(AuditLog(action='bulk_findings_sent_to_iris', object_type='finding', detail=f'sent={sent}'))
    db.commit()
    return RedirectResponse('/tickets', status_code=303)

@app.get('/reports/findings.csv')
def report_findings_csv(db: Session = Depends(get_db)):
    findings = active_findings_query(db).order_by(Finding.risk_score.desc(), Finding.id.desc()).all()
    return Response(
        content=export_findings_csv(findings),
        media_type='text/csv',
        headers={'Content-Disposition': 'attachment; filename="satria-findings.csv"'}
    )

@app.get('/reports/findings.xlsx')
def report_findings_xlsx(db: Session = Depends(get_db)):
    findings = active_findings_query(db).order_by(Finding.risk_score.desc(), Finding.id.desc()).all()
    return Response(
        content=export_findings_xlsx(findings),
        media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': 'attachment; filename="satria-findings.xlsx"'}
    )

@app.get('/reports/executive.md')
def report_executive_md(db: Session = Depends(get_db)):
    summary = get_summary(db)
    return PlainTextResponse(
        content=executive_markdown_report(summary),
        media_type='text/markdown',
        headers={'Content-Disposition': 'attachment; filename="satria-executive-summary.md"'}
    )

@app.get('/api/summary')
def api_summary(db: Session = Depends(get_db)):
    summary = get_summary(db)
    # Remove ORM objects from API response.
    return {
        key: value for key, value in summary.items()
        if key not in {'recent_scans', 'latest_findings'}
    }


@app.get('/api/assets', response_model=list[AssetOut])
def api_assets(db: Session = Depends(get_db)):
    return db.query(Asset).order_by(Asset.id.desc()).all()

@app.post('/api/assets', response_model=AssetOut)
def api_create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    asset = Asset(**payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset

@app.get('/api/scans', response_model=list[ScanOut])
def api_scans(db: Session = Depends(get_db)):
    return (
        db.query(ScanJob)
        .filter(ScanJob.is_visible == True)
        .order_by(ScanJob.id.desc())
        .limit(200)
        .all()
    )

@app.post('/api/scans', response_model=ScanOut)
def api_create_scan(payload: ScanCreate, db: Session = Depends(get_db)):
    asset = db.get(Asset, payload.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail='asset not found')
    if payload.profile not in SUPPORTED_PROFILES:
        raise HTTPException(status_code=400, detail='unsupported scan profile')
    job = ScanJob(asset_id=asset.id, profile=payload.profile, scanner='+'.join(scanners_for_profile(payload.profile)), status='queued')
    db.add(job)
    db.commit()
    db.refresh(job)
    run_scan_job.delay(job.id)
    return job

@app.get('/api/findings', response_model=list[FindingOut])
def api_findings(db: Session = Depends(get_db)):
    return active_findings_query(db).order_by(Finding.risk_score.desc(), Finding.id.desc()).limit(500).all()


def _ticket_case_view(ticket: TicketCase, remote_case: dict | None = None) -> dict:
    settings = get_settings()
    return {
        'classification': (remote_case or {}).get('classification') or classification_label_for_case(ticket),
        'soc_id': (remote_case or {}).get('case_soc_id') or ticket.remote_case_soc_id or default_soc_id_for_case(ticket),
        'customer': (remote_case or {}).get('client_name') or (remote_case or {}).get('customer_name') or settings.iris_customer_name,
        'tags': tags_for_case(ticket),
        'remote_state': (remote_case or {}).get('state_name') or ticket.status,
        'remote_owner': (remote_case or {}).get('owner') or ticket.current_owner or '-',
        'remote_open_date': (remote_case or {}).get('case_open_date') or (remote_case or {}).get('open_date') or '-',
        'remote_name': (remote_case or {}).get('case_name') or ticket.remote_case_name or ticket.title,
    }


def _iris_login_url() -> str | None:
    settings = get_settings()
    if not settings.iris_url:
        return None
    return f"{settings.iris_url.rstrip('/')}/login"
