"""Manual WSTG assessments backed by SATRIA assets, findings and audit logs."""
import base64
import binascii
from datetime import datetime
import json
from pathlib import Path
import uuid

from .cvss_reference import ReferenceCVSS4 as CVSS4
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .database import get_db
from .models import (Asset, Assessment, AssessmentFinding, AssessmentFindingImage,
                     AssessmentResult, AssessmentResultImage, AuditLog, Finding, ScanJob)
from .risk import normalize_severity, risk_score

STATIC = Path(__file__).parent / 'static' / 'assessments'
CATALOG = json.loads((STATIC / 'wstg-data.json').read_text(encoding='utf-8'))
CODES = {item['code'] for item in CATALOG}
METRICS = json.loads((STATIC / 'cvss-metrics.json').read_text(encoding='utf-8'))
BASE_METRICS = list(METRICS)[:11]
STATUSES = {'Not Started', 'In Progress', 'Completed', 'Not Applicable'}
CATEGORIES = {f'A{i:02}:2021' for i in range(1, 11)}
MAX_BODY = 22 * 1024 * 1024
templates = Jinja2Templates(directory='app/templates')


def require_user(request: Request):
    if not getattr(request.state, 'current_user', None):
        raise HTTPException(401, 'Silakan login ke SATRIA.')
    if request.method not in {'GET', 'HEAD'}:
        origin = request.headers.get('origin')
        if request.headers.get('sec-fetch-site') == 'cross-site' or (origin and origin != str(request.base_url).rstrip('/')):
            raise HTTPException(403, 'Permintaan harus berasal dari SATRIA.')


router = APIRouter(prefix='/assessments', dependencies=[Depends(require_user)])


async def payload(request: Request):
    if request.headers.get('content-type', '').split(';')[0] != 'application/json':
        raise HTTPException(415, 'Gunakan Content-Type application/json.')
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > MAX_BODY:
            raise HTTPException(413, 'Payload terlalu besar.')
    try:
        value = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(400, 'Body JSON tidak valid.')
    if not isinstance(value, dict):
        raise HTTPException(400, 'Body harus berupa objek JSON.')
    return value


def text(value, label, maximum=20000, required=False):
    if value is None:
        value = ''
    if not isinstance(value, str) or len(value) > maximum:
        raise HTTPException(400, f'{label} tidak valid atau terlalu panjang.')
    if required and not value.strip():
        raise HTTPException(400, f'{label} wajib diisi.')
    return value.strip()


def code(value, required=False):
    value = text(value, 'Kode WSTG', 100, required)
    if value and value not in CODES:
        raise HTTPException(400, 'Kode WSTG tidak ada dalam katalog.')
    return value


def rating(vector):
    vector = text(vector, 'Vector CVSS 4.0', 512, True)
    if not vector.startswith('CVSS:4.0/'):
        raise HTTPException(400, 'Hanya CVSS 4.0 yang didukung.')
    order = list(METRICS)
    selected, previous = {}, -1
    for part in vector.split('/')[1:]:
        pair = part.split(':')
        if len(pair) != 2 or pair[0] not in METRICS or pair[1] not in METRICS[pair[0]]:
            raise HTTPException(400, 'Metrik CVSS 4.0 tidak valid.')
        key, value = pair
        index = order.index(key)
        if index <= previous:
            raise HTTPException(400, 'Urutan metrik tidak valid atau duplikat.')
        selected[key], previous = value, index
    if not all(key in selected for key in BASE_METRICS):
        raise HTTPException(400, 'Lengkapi seluruh 11 metrik Base CVSS 4.0.')
    canonical = 'CVSS:4.0/' + '/'.join(f'{key}:{value}' for key, value in selected.items() if value != 'X')
    try:
        score = float(CVSS4(canonical).scores()[0])
    except (ValueError, KeyError) as error:
        raise HTTPException(400, 'Vector CVSS 4.0 tidak valid.') from error
    severity = 'None' if score == 0 else 'Low' if score < 4 else 'Medium' if score < 7 else 'High' if score < 9 else 'Critical'
    return canonical, score, severity


def assessment_or_404(db, id):
    item = db.get(Assessment, id)
    if not item:
        raise HTTPException(404, 'Assessment tidak ditemukan.')
    return item


def finding_or_404(db, id):
    item = db.get(AssessmentFinding, id)
    if not item:
        raise HTTPException(404, 'Temuan assessment tidak ditemukan.')
    return item


def audit(db, request, action, item):
    db.add(AuditLog(actor=request.state.current_user, action=action, object_type='assessment', object_id=str(item.id)))
    item.updated_at = datetime.utcnow()


def image_meta(image):
    return {'id': image.id, 'name': image.name, 'mime': image.mime, 'size': len(image.image)}


def validate_images(incoming, existing):
    if incoming is None:
        return None
    if not isinstance(incoming, list) or len(incoming) > 5:
        raise HTTPException(400, 'Maksimal 5 gambar per catatan.')
    known = {image.id: image for image in existing}
    parsed, seen, total = [], set(), 0
    for item in incoming:
        if not isinstance(item, dict):
            raise HTTPException(400, 'Gambar tidak valid.')
        if 'id' in item:
            id = item['id']
            if type(id) is not int or id in seen or id not in known:
                raise HTTPException(400, 'Gambar bukan milik catatan ini atau duplikat.')
            seen.add(id)
            total += len(known[id].image)
            parsed.append(known[id])
            continue
        name = text(item.get('name'), 'Nama gambar', 200) or 'Screenshot.png'
        value = item.get('dataUrl')
        if not isinstance(value, str) or ';base64,' not in value:
            raise HTTPException(400, 'Data gambar tidak valid.')
        prefix, encoded = value.split(';base64,', 1)
        mime = prefix.removeprefix('data:')
        if prefix != 'data:' + mime or mime not in {'image/png', 'image/jpeg', 'image/webp'}:
            raise HTTPException(400, 'Gunakan PNG, JPEG, atau WebP.')
        try:
            binary = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise HTTPException(400, 'Encoding gambar tidak valid.')
        if len(binary) > 5 * 1024 * 1024:
            raise HTTPException(413, 'Ukuran setiap gambar maksimal 5 MB.')
        valid = (mime == 'image/png' and binary.startswith(b'\x89PNG\r\n\x1a\n')) or (mime == 'image/jpeg' and binary.startswith(b'\xff\xd8\xff')) or (mime == 'image/webp' and binary[:4] == b'RIFF' and binary[8:12] == b'WEBP')
        if not valid:
            raise HTTPException(400, 'Isi gambar tidak sesuai format.')
        parsed.append({'name': name, 'mime': mime, 'image': binary})
        total += len(binary)
    if total > 15 * 1024 * 1024:
        raise HTTPException(413, 'Total gambar maksimal 15 MB.')
    return parsed


def replace_images(owner, parsed, model):
    if parsed is not None:
        owner.images = [model(**item) if isinstance(item, dict) else item for item in parsed]


def assessment_data(item):
    return {'id': item.id, 'asset_id': item.asset_id, 'name': item.name, 'target': item.asset.target,
            'environment': item.environment, 'scope': item.scope, 'owner_name': item.owner_name,
            'created_at': item.created_at.isoformat(), 'updated_at': item.updated_at.isoformat(),
            'completed': sum(r.status == 'Completed' for r in item.results),
            'inProgress': sum(r.status == 'In Progress' for r in item.results),
            'findings': len(item.finding_details),
            'critical': sum(f.finding.severity_normalized == 'Critical' for f in item.finding_details)}


def finding_data(item):
    f = item.finding
    return {'id': f.id, 'test_code': item.test_code, 'title': f.title,
            'affected_path': f.affected_component or '', 'observation': f.description or '',
            'recommendation': f.recommendation or '', 'impact_description': item.impact_description,
            'owaspCategories': json.loads(item.owasp_categories), 'cvss_vector': item.cvss_vector,
            'cvss_score': f'{f.cvss_score:.1f}', 'scoring_method': 'CVSS:4.0',
            'severity': 'None' if f.cvss_score == 0 else f.severity_normalized, 'status': f.status,
            'evidenceImages': [image_meta(image) for image in item.images], 'finding_url': f'/findings/{f.id}'}


@router.get('')
def page(request: Request):
    return templates.TemplateResponse('assessments.html', {'request': request})


@router.get('/workspace')
def workspace(request: Request):
    return templates.TemplateResponse('assessment_workspace.html', {'request': request}, headers={'X-Frame-Options': 'SAMEORIGIN', 'Cache-Control': 'no-store'})


@router.get('/api/assets')
def assets(db: Session = Depends(get_db)):
    return {'assets': [{'id': a.id, 'name': a.name, 'target': a.target, 'environment': a.environment} for a in db.query(Asset).filter(Asset.is_active.is_(True)).order_by(Asset.name)]}


@router.get('/api/assessments')
def listing(db: Session = Depends(get_db)):
    return {'assessments': [assessment_data(a) for a in db.query(Assessment).order_by(Assessment.updated_at.desc())]}


@router.post('/api/assessments', status_code=201)
async def create(request: Request, db: Session = Depends(get_db)):
    b = await payload(request)
    if type(b.get('assetId')) is not int:
        raise HTTPException(400, 'Pilih aset SATRIA.')
    asset = db.get(Asset, b['assetId'])
    if not asset or not asset.is_active:
        raise HTTPException(400, 'Aset tidak ditemukan atau sudah diarsipkan.')
    name, scope = text(b.get('name'), 'Nama assessment', 200, True), text(b.get('scope'), 'Rules of Engagement (RoE)')
    # Internal grouping record only: never enqueued, scanned, or shown as a scan.
    scan = ScanJob(asset_id=asset.id, profile='manual_assessment', scanner='manual-wstg', status='completed', is_visible=False, message='Manual WSTG assessment; no scanner executed.')
    db.add(scan)
    db.flush()
    item = Assessment(asset_id=asset.id, scan_job_id=scan.id, name=name, scope=scope, environment=asset.environment, owner_name=request.state.current_user)
    db.add(item)
    db.flush()
    audit(db, request, 'assessment_created', item)
    db.commit()
    return {'assessment': {'id': item.id}}


@router.patch('/api/assessments/{id}/scope')
async def update_scope(id: int, request: Request, db: Session = Depends(get_db)):
    item = assessment_or_404(db, id)
    body = await payload(request)
    if 'scope' not in body or not isinstance(body['scope'], str):
        raise HTTPException(400, 'Rules of Engagement (RoE) harus berupa teks.')
    item.scope = text(body['scope'], 'Rules of Engagement (RoE)')
    audit(db, request, 'assessment_scope_updated', item)
    db.commit()
    return {'scope': item.scope}


@router.get('/api/assessments/{id}')
def detail(id: int, db: Session = Depends(get_db)):
    item = assessment_or_404(db, id)
    return {'assessment': assessment_data(item), 'results': [
        {'id': r.id, 'test_code': r.test_code, 'status': r.status, 'remark': r.remark, 'evidence_url': r.evidence_url, 'tester_name': r.tester_name} for r in item.results],
        'findings': [finding_data(f) for f in sorted(item.finding_details, key=lambda f: f.finding_id, reverse=True)],
        'evidenceImages': [{**image_meta(image), 'test_code': r.test_code} for r in item.results for image in r.images]}


def can_delete(item):
    if item.finding.ticket_case or item.finding.iris_alert_id:
        raise HTTPException(409, 'Temuan sudah terkait tiket. Selesaikan tindak lanjut melalui Findings/Tickets; data tiket tidak dihapus dari Assessments.')


@router.delete('/api/assessments/{id}')
def delete(id: int, request: Request, db: Session = Depends(get_db)):
    item = assessment_or_404(db, id)
    for f in item.finding_details:
        can_delete(f)
    audit(db, request, 'assessment_deleted', item)
    for f in list(item.finding_details):
        db.delete(f.finding)
    db.flush()
    # Expire the collection so ORM does not try to null deleted children's FK.
    db.expire(item, ['finding_details'])
    scan = item.scan_job
    db.delete(item)
    db.flush()
    db.delete(scan)
    db.commit()
    return {'ok': True}


@router.put('/api/assessments/{id}/results')
async def save_result(id: int, request: Request, db: Session = Depends(get_db)):
    item, b = assessment_or_404(db, id), await payload(request)
    test_code = code(b.get('testCode'), True)
    status = b.get('status', 'Not Started')
    if not isinstance(status, str) or status not in STATUSES:
        raise HTTPException(400, 'Status pengujian tidak valid.')
    result = next((r for r in item.results if r.test_code == test_code), None)
    images = validate_images(b.get('evidenceImages'), result.images if result else [])
    remark, url = text(b.get('remark'), 'Catatan'), text(b.get('evidenceUrl'), 'Tautan evidence', 4000)
    if result is None:
        result = AssessmentResult(assessment=item, test_code=test_code)
        db.add(result)
    result.status, result.remark, result.evidence_url = status, remark, url
    result.tester_name, result.updated_at = request.state.current_user, datetime.utcnow()
    replace_images(result, images, AssessmentResultImage)
    audit(db, request, 'assessment_result_saved', item)
    db.commit()
    return {'ok': True}


def save_finding(db, request, assessment, b, entry=None):
    vector, score, severity = rating(b.get('cvssVector'))
    title = text(b.get('title'), 'Nama kerentanan', 300, True)
    test_code = code(b.get('testCode'))
    path = text(b.get('affectedPath'), 'Path', 4000)
    description, recommendation = text(b.get('observation'), 'Deskripsi'), text(b.get('recommendation'), 'Rekomendasi')
    impact = text(b.get('impactDescription', entry.impact_description if entry else ''), 'Dampak')
    categories = b.get('owaspCategories', json.loads(entry.owasp_categories) if entry else [])
    if not isinstance(categories, list) or len(categories) > 10 or any(not isinstance(c, str) or c not in CATEGORIES for c in categories) or len(set(categories)) != len(categories):
        raise HTTPException(400, 'Kategori OWASP Top 10:2021 tidak valid.')
    images = validate_images(b.get('evidenceImages'), entry.images if entry else [])
    if entry is None:
        finding = Finding(asset_id=assessment.asset_id, scan_job_id=assessment.scan_job_id, scanner='manual-wstg', finding_type='manual_assessment', dedup_key=f'manual-wstg:{uuid.uuid4()}')
        entry = AssessmentFinding(assessment=assessment, finding=finding)
        db.add(finding)
    else:
        finding = entry.finding
    finding.title, finding.description, finding.affected_component = title, description, path
    finding.recommendation = recommendation
    finding.cvss_score, finding.severity_original, finding.severity_normalized = score, severity, normalize_severity(severity)
    finding.risk_score = risk_score(severity, assessment.asset.criticality, score)
    finding.last_seen_at = datetime.utcnow()
    entry.test_code, entry.cvss_vector, entry.impact_description = test_code, vector, impact
    entry.owasp_categories = json.dumps(categories)
    replace_images(entry, images, AssessmentFindingImage)
    db.flush()
    finding.evidence = f'Assessment #{assessment.id}\nWSTG: {test_code}\n{vector}\nOWASP: {", ".join(categories)}\nDampak: {impact}\n' + '\n'.join(f'/assessments/api/finding-evidence/{image.id}' for image in entry.images)
    audit(db, request, 'assessment_finding_saved', assessment)
    db.commit()
    return finding


@router.post('/api/assessments/{id}/findings', status_code=201)
async def create_finding(id: int, request: Request, db: Session = Depends(get_db)):
    f = save_finding(db, request, assessment_or_404(db, id), await payload(request))
    return {'finding': {'id': f.id}}


@router.put('/api/findings/{id}')
async def update_finding(id: int, request: Request, db: Session = Depends(get_db)):
    entry = finding_or_404(db, id)
    save_finding(db, request, entry.assessment, await payload(request), entry)
    return {'ok': True}


@router.delete('/api/findings/{id}')
def delete_finding(id: int, request: Request, db: Session = Depends(get_db)):
    entry = finding_or_404(db, id)
    can_delete(entry)
    audit(db, request, 'assessment_finding_deleted', entry.assessment)
    db.delete(entry.finding)
    db.commit()
    return {'ok': True}


@router.get('/api/{kind}/{id}')
def image(kind: str, id: int, db: Session = Depends(get_db)):
    model = {'evidence': AssessmentResultImage, 'finding-evidence': AssessmentFindingImage}.get(kind)
    item = db.get(model, id) if model else None
    if not item:
        raise HTTPException(404, 'Gambar tidak ditemukan.')
    return Response(item.image, media_type=item.mime, headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})
