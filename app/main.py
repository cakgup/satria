import hashlib
from datetime import datetime
import json
from pathlib import Path
import re
import secrets
from urllib.parse import quote_plus
from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from .database import get_db, init_db
from .allowlist import configured_allowlist_rules, database_allowlist_entries
from .config import get_settings
from .models import AppSetting, Asset, AuditLog, Finding, ReleaseArtifact, ScanAllowlistEntry, ScanJob, ServiceAccountCredential, TicketCase
from .schemas import AssetCreate, AssetOut, FindingOut, PipelinePublishTicketOut, PipelinePublishTicketRequest, PipelineScanCreate, PipelineScanResultOut, PipelineScanStatusOut, PipelineSeveritySummary, ReleaseIntakeCreate, ReleaseIntakeOut, ScanCreate, ScanOut
from .scanner_runner import SUPPORTED_PROFILES, scanners_for_profile
from .tasks import run_scan_job
from .iris import delete_remote_ticket_case, get_remote_case_bundle, import_remote_cases_to_satria, list_remote_cases, refresh_ticket_case_from_iris, send_finding_to_iris, sync_ticket_case
from .reporting import active_findings_query, count_pie_segments, count_pie_style, get_summary, severity_pie_segments, severity_pie_style, export_findings_csv, export_findings_xlsx, executive_markdown_report
from .soc import MANUAL_PLAYBOOKS, SOC_DEMO_USERS, SOC_SOP, classification_label_for_case, default_soc_id_for_case, playbook_choices, tags_for_case
from .ticketing import add_ticket_activity, add_ticket_evidence, add_ticket_task, create_manual_case_from_playbook, seed_demo_manual_cases, update_ticket_case

app = FastAPI(title='SATRIA', version='0.1.0-mvp')
app.mount('/static', StaticFiles(directory='app/static'), name='static')
templates = Jinja2Templates(directory='app/templates')

ADMIN_USERS = {'administrator', 'admin', 'cakgup1', 'top-management'}
API_SCOPE_OPTIONS = [
    {
        'value': 'release:write',
        'label': 'Release Intake',
        'description': 'Mendaftarkan artefak release dari Jenkins, GitLab CI, atau pipeline lain.',
    },
    {
        'value': 'scan:create',
        'label': 'Create Scan',
        'description': 'Membuat scan job SATRIA berdasarkan artefak atau aset yang sudah diintake.',
    },
    {
        'value': 'scan:read',
        'label': 'Read Scan Result',
        'description': 'Membaca status, summary, dan hasil scan untuk keperluan gate pipeline.',
    },
    {
        'value': 'ticket:publish',
        'label': 'Publish Ticket',
        'description': 'Mengirim temuan terpilih dari SATRIA ke IRIS bila dibutuhkan remediation formal.',
    },
]
API_SCOPE_VALUES = {option['value'] for option in API_SCOPE_OPTIONS}
GATE_DECISION_OPTIONS = [
    {'value': 'allowed', 'label': 'Allowed'},
    {'value': 'need_approval', 'label': 'Need Approval'},
    {'value': 'blocked', 'label': 'Blocked'},
]
GATE_DECISION_VALUES = {option['value'] for option in GATE_DECISION_OPTIONS}
GATE_SETTING_KEYS = (
    'gate_policy_name',
    'gate_block_on_critical',
    'gate_high_threshold',
    'gate_high_decision',
    'gate_medium_threshold',
    'gate_medium_decision',
    'gate_low_threshold',
    'gate_low_decision',
)

PUBLIC_PATH_PREFIXES = (
    '/static',
    '/login',
    '/health',
    '/api/v1',
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
        'sub_guides': {
            'pipeline': {
                'label': 'Interkoneksi pipeline CI/CD',
                'hero': 'Panduan integrasi SATRIA ke pipeline CI/CD sebelum artefak dipromosikan ke staging atau production.',
                'summary': 'Gunakan panduan ini saat SATRIA diposisikan sebagai security gate pada jalur build-release, misalnya melalui Jenkins, GitLab CI, atau pipeline internal lainnya, agar artefak release diperiksa, diberi keputusan gate, dan bila perlu diteruskan ke workflow ticketing sebelum promosi release.',
                'cards': [
                    {'title': 'Pola minimum', 'value': 'Build -> Push -> Intake -> Scan -> Gate', 'caption': 'Urutan minimum yang selaras dengan UR interkoneksi CI/CD'},
                    {'title': 'Akses integrasi', 'value': 'Bearer token service account', 'caption': 'Pipeline cukup memakai token non-personal yang disimpan di credential store Jenkins/GitLab'},
                    {'title': 'Keputusan gate', 'value': 'allowed / blocked / need_approval', 'caption': 'Pipeline membaca keputusan SATRIA untuk menentukan promote, stop, atau manual approval'},
                    {'title': 'Output tindak lanjut', 'value': 'SATRIA -> IRIS', 'caption': 'Temuan berat dapat dipublish menjadi ticket IRIS setelah hasil scan terbukti relevan'},
                ],
                'sections': [
                    {'title': 'Tujuan dan posisi SATRIA di jalur CI/CD', 'items': [
                        'SATRIA diposisikan sebagai gerbang pemeriksaan keamanan terhadap artefak release sebelum deployment production, bukan sebagai pengganti build system, registry internal, atau change management yang sudah berjalan.',
                        'Pipeline tetap menjalankan tahapan rekayasa perangkat lunak seperti checkout source, unit test, build, dan push image, sedangkan SATRIA berperan menerima intake release, membuat scan job, menyajikan hasil, dan mengembalikan keputusan gate.',
                        'Dengan pola ini, setiap image release yang akan dipromosikan memiliki jejak audit yang jelas: siapa yang membangun, image mana yang diperiksa, profile scan apa yang digunakan, serta mengapa release diizinkan atau ditahan.',
                    ]},
                    {'title': 'Alur proses end-to-end yang diharapkan', 'items': [
                        'Pipeline melakukan checkout source code dan quality gate dasar internal seperti unit test, static validation, atau tahapan build verification lain yang sudah berlaku.',
                        'Pipeline membangun container image, memberi tag release yang jelas dan immutable, lalu melakukan push ke internal registry.',
                        'Pipeline mengirim intake release ke SATRIA atau mengaitkan artefak dengan aset yang sudah terdaftar, minimal dengan data asset_code, asset_name, release_version, image_ref, image_digest, git_commit, build_number, dan environment_target.',
                        'Pipeline membuat scan job SATRIA menggunakan profile yang sesuai, misalnya quick_container untuk gate cepat, full_container untuk aplikasi kritikal, atau sbom_scan untuk kebutuhan inventaris komponen.',
                        'SATRIA melakukan pull image dari registry internal, menjalankan scanner, dan memperbarui status job dari queued ke running hingga completed, failed, cancelled, atau timeout.',
                        'Pipeline melakukan polling status scan berdasarkan scan_id sampai hasil tersedia, kemudian membaca hasil JSON terstruktur untuk mengambil keputusan gate.',
                        'Jika hasil dinyatakan allowed, pipeline dapat melanjutkan approval atau deploy sesuai tata kelola perubahan. Jika blocked, pipeline berhenti. Jika need_approval, pipeline masuk ke approval khusus atau risk acceptance yang sah.',
                        'Temuan dengan tingkat risiko yang perlu remediation formal dapat dipublish dari SATRIA ke IRIS agar ada case, task, dan audit tindak lanjut resmi.',
                    ]},
                    {'title': 'Peran aktor yang terlibat', 'items': [
                        'Tim Pengembang memastikan source code, dependency, dan artefak image dibangun dari branch yang benar, serta release version konsisten dengan commit yang diajukan.',
                        'Tim DevOps mengelola Jenkins, GitLab CI, runner, registry, service account, secret pipeline, jalur jaringan, dan endpoint integrasi ke SATRIA.',
                        'Operator SATRIA mengelola scan profile, engine scanner, policy severity, threshold gate, allowlist registry, dan monitoring job yang dibuat oleh pipeline.',
                        'Pemilik Sistem atau Change Approver menggunakan hasil scan SATRIA sebagai salah satu dasar keputusan apakah release dapat diteruskan, ditahan, atau harus melalui jalur pengecualian.',
                        'Tim Keamanan Informasi menetapkan rule gate, severity threshold, mekanisme exception, risk acceptance, dan pola publish ke IRIS bila temuan memerlukan pelacakan resmi.',
                    ]},
                    {'title': 'Persiapan administrasi dan token integrasi', 'intro': [
                        'Pada implementasi SATRIA saat ini, token pipeline sebaiknya dikelola melalui menu Admin Token pada SATRIA oleh administrator aplikasi. Dengan demikian, proses awal yang perlu dilakukan pengembang adalah meminta pembuatan service account dan token integrasi kepada operator SATRIA atau administrator platform.',
                        'Token ini sebaiknya berbeda untuk setiap pipeline utama atau minimal setiap lini aplikasi besar, agar audit trail tetap jelas dan rotasi credential lebih mudah dilakukan.'
                    ], 'items': [
                        'Administrator SATRIA menetapkan nama akun layanan, misalnya pipeline-sakti-api atau jenkins-prod-gate.',
                        'Administrator SATRIA mengisi token pada environment variable SATRIA_API_TOKEN dan membatasi hak aksesnya melalui SATRIA_API_SCOPES.',
                        'Scope minimum yang disarankan untuk kebutuhan gate adalah release:write, scan:create, dan scan:read. Tambahkan ticket:publish hanya bila pipeline memang diizinkan membuat ticket ke IRIS.',
                        'Token kemudian disimpan di Jenkins Credentials, GitLab CI Variables, atau secret manager internal. Jangan hardcode token di Jenkinsfile, YAML, atau repository aplikasi.',
                        'Bila token perlu diputar, administrator mengganti nilai SATRIA_API_TOKEN di server SATRIA, memperbarui secret pada CI/CD, lalu menguji ulang endpoint /api/v1/releases/intake dan /api/v1/scans.',
                    ], 'snippets': [
                        {
                            'title': 'Contoh konfigurasi environment di server SATRIA (.env backend)',
                            'code': 'SATRIA_API_SERVICE_ACCOUNT=pipeline-service\nSATRIA_API_TOKEN=replace-with-long-random-token\nSATRIA_API_SCOPES=release:write,scan:create,scan:read,ticket:publish\nGATE_POLICY_NAME=ur-production-gate\nGATE_BLOCK_ON_CRITICAL=true\nGATE_HIGH_THRESHOLD=1\nGATE_HIGH_DECISION=need_approval\nGATE_MEDIUM_THRESHOLD=15\nGATE_MEDIUM_DECISION=need_approval\nGATE_LOW_THRESHOLD=9999\nGATE_LOW_DECISION=allowed'
                        },
                        {
                            'title': 'Header yang dipakai pipeline saat memanggil API SATRIA',
                            'code': 'Authorization: Bearer ${SATRIA_TOKEN}\nContent-Type: application/json'
                        },
                    ], 'note': 'Pembuatan token tetap dikendalikan administrator SATRIA agar kontrol akses, audit trail, dan rotasi credential tetap terjaga.'},
                    {'title': 'Langkah praktis mendapatkan API key atau token SATRIA', 'items': [
                        'Ajukan permintaan service account integrasi kepada administrator SATRIA dengan menyebutkan nama aplikasi, nama pipeline, environment, dan PIC teknis yang bertanggung jawab.',
                        'Sampaikan minimal data berikut dalam permintaan: asset_code, asset_name, jenis artefak yang akan dipindai, registry yang dipakai, serta environment target seperti staging atau production.',
                        'Minta scope yang benar-benar diperlukan. Untuk pola gate minimum cukup gunakan release:write, scan:create, dan scan:read. Tambahkan ticket:publish hanya jika pipeline memang boleh mengirim tiket ke IRIS.',
                        'Setelah token diberikan administrator, simpan token itu di credential store CI/CD. Jangan pernah meletakkan token dalam file Jenkinsfile, repository source code, atau channel komunikasi yang tidak terenkripsi.',
                        'Lakukan uji koneksi awal menggunakan endpoint POST /api/v1/releases/intake. Bila respons berhasil, lanjutkan ke uji create scan dan polling hasil sebelum token dinyatakan siap operasional.',
                    ], 'snippets': [
                        {
                            'title': 'Contoh format permintaan token ke administrator SATRIA',
                            'code': 'Nama aplikasi      : SAKTI API\nNama pipeline      : jenkins-sakti-api-prod\nEnvironment        : production\nAsset code         : SAKTI-API\nJenis artefak      : container_image\nRegistry           : registry.internal/sakti-api\nScope dibutuhkan   : release:write,scan:create,scan:read,ticket:publish\nPIC teknis         : Tim DevOps DJPb\nKebutuhan publish  : hanya critical/high ke IRIS'
                        },
                        {
                            'title': 'Uji koneksi minimal setelah token diterima',
                            'code': 'curl -X POST "$SATRIA_URL/api/v1/releases/intake" \\\n  -H "Authorization: Bearer $SATRIA_TOKEN" \\\n  -H "Content-Type: application/json" \\\n  -d "{\\"asset_code\\":\\"TEST-CICD\\",\\"asset_name\\":\\"Test CICD\\",\\"release_version\\":\\"smoke-001\\",\\"image_ref\\":\\"nginx:latest\\",\\"build_number\\":\\"1\\",\\"environment_target\\":\\"staging\\"}"'
                        },
                    ], 'note': 'Prinsip sederhananya: token SATRIA diperlakukan sama seperti password teknis. Ia hanya boleh disimpan di secret manager atau credential store resmi dan harus bisa diputar sewaktu-waktu tanpa mengubah source code aplikasi.'},
                    {'title': 'Kebutuhan integrasi minimum yang perlu disiapkan', 'items': [
                        'SATRIA perlu menyediakan API atau CLI resmi untuk intake release, pembuatan scan job, pengecekan status, pengambilan hasil JSON, dan publish ticket bila diperlukan.',
                        'Pipeline sebaiknya menggunakan service account non-personal dengan autentikasi token, bearer token, API key, atau mekanisme sejenis yang dapat dibatasi scope-nya.',
                        'Server SATRIA harus dapat mengakses internal registry untuk pull image, termasuk DNS resolution, firewall rule, TLS trust, dan credential read-only atau pull-only.',
                        'Pipeline harus mengirim metadata release secara lengkap agar audit trail terbentuk, termasuk asset_code, release_version, image digest, git commit, build number, dan target environment.',
                        'Scan profile yang dipakai pipeline harus sudah disetujui operator SATRIA, serta dapat dipetakan ke kritikalitas aset dan jenis keputusan gate yang diinginkan.',
                    ]},
                    {'title': 'Field intake release yang wajib dipetakan dari pipeline', 'intro': [
                        'Bagian ini menjawab pertanyaan paling umum dari tim pengembang: field apa saja yang harus diisi dari Jenkins atau GitLab CI agar SATRIA dapat mengenali artefak release dengan benar. Semakin lengkap metadata yang dikirim, semakin baik kualitas audit trail dan pelacakan hasil scan.'
                    ], 'items': [
                        'asset_code: kode aset/aplikasi yang konsisten antar release, misalnya SAKTI-API.',
                        'asset_name: nama bisnis atau nama aplikasi yang akan tampil pada SATRIA, misalnya SAKTI API.',
                        'release_version: versi release immutable, misalnya release-2026.07.04-201-a1b2c3d4.',
                        'image_ref: referensi image bertag, misalnya registry.internal/sakti-api:release-2026.07.04-201-a1b2c3d4.',
                        'image_digest: digest image hasil push ke registry, agar SATRIA memindai artefak yang benar-benar akan dipromosikan.',
                        'git_commit: commit SHA yang membentuk release tersebut.',
                        'build_number: nomor build CI/CD, misalnya BUILD_NUMBER Jenkins atau CI_PIPELINE_ID GitLab.',
                        'environment_target: target promosi release, misalnya staging atau production.',
                        'risk_acceptance_ref: nomor dokumen pengecualian bila sudah ada keputusan resmi yang berlaku.',
                        'gate_override_decision: dipakai sangat terbatas untuk kasus override formal yang telah disetujui, misalnya allowed walau ada high tertentu.',
                    ], 'snippets': [
                        {
                            'title': 'Payload JSON intake release yang direkomendasikan',
                            'code': '{\n  "asset_code": "SAKTI-API",\n  "asset_name": "SAKTI API",\n  "release_version": "release-2026.07.04-201-a1b2c3d4",\n  "image_ref": "registry.internal/sakti-api:release-2026.07.04-201-a1b2c3d4",\n  "image_digest": "registry.internal/sakti-api@sha256:abc123...",\n  "git_commit": "a1b2c3d4",\n  "build_number": "201",\n  "environment_target": "production",\n  "risk_acceptance_ref": "RA-2026-001",\n  "gate_override_decision": null\n}'
                        },
                    ]},
                    {'title': 'Contoh endpoint atau kontrak integrasi minimum', 'items': [
                        'POST /api/v1/releases/intake untuk mendaftarkan atau mengaitkan release image ke aset SATRIA.',
                        'POST /api/v1/scans untuk membuat scan job dengan parameter asset_id, release_id, image_ref, scan_profile, requested_by, dan build_number.',
                        'GET /api/v1/scans/{scan_id} untuk membaca status job seperti queued, running, completed, failed, cancelled, atau timeout.',
                        'GET /api/v1/scans/{scan_id}/result untuk mengambil hasil JSON terstruktur yang berisi severity summary, gate decision, report URL, dan detail finding utama.',
                        'POST /api/v1/scans/{scan_id}/publish-ticket untuk meneruskan finding yang relevan ke IRIS bila organisasi membutuhkan remediation formal.',
                    ]},
                    {'title': 'Urutan panggilan API yang direkomendasikan dari pipeline', 'intro': [
                        'Secara praktis, pipeline tidak perlu mengetahui detail internal SATRIA. Pipeline cukup menjalankan lima tahap panggilan API: intake release, create scan, polling status, ambil hasil, lalu publish ticket bila perlu.'
                    ], 'items': [
                        'Langkah 1: pipeline memanggil POST /api/v1/releases/intake dan menyimpan release_id dari response.',
                        'Langkah 2: pipeline memanggil POST /api/v1/scans menggunakan release_id, image_ref, scan_profile, requested_by, dan build_number; SATRIA mengembalikan scan_id.',
                        'Langkah 3: pipeline melakukan polling GET /api/v1/scans/{scan_id} sampai status mencapai completed, failed, cancelled, atau timeout.',
                        'Langkah 4: bila completed, pipeline memanggil GET /api/v1/scans/{scan_id}/result dan membaca summary, decision, policy_name, risk_acceptance_ref, serta report_url.',
                        'Langkah 5: bila severity tertentu harus masuk workflow resmi, pipeline atau operator memanggil POST /api/v1/scans/{scan_id}/publish-ticket.',
                    ], 'snippets': [
                        {
                            'title': 'Contoh sequence curl minimal',
                            'code': 'curl -X POST "$SATRIA_URL/api/v1/releases/intake" \\\n  -H "Authorization: Bearer $SATRIA_TOKEN" \\\n  -H "Content-Type: application/json" \\\n  -d @release-intake.json\n\ncurl -X POST "$SATRIA_URL/api/v1/scans" \\\n  -H "Authorization: Bearer $SATRIA_TOKEN" \\\n  -H "Content-Type: application/json" \\\n  -d @scan-request.json\n\ncurl -H "Authorization: Bearer $SATRIA_TOKEN" \\\n  "$SATRIA_URL/api/v1/scans/$SCAN_ID"\n\ncurl -H "Authorization: Bearer $SATRIA_TOKEN" \\\n  "$SATRIA_URL/api/v1/scans/$SCAN_ID/result"\n\ncurl -X POST "$SATRIA_URL/api/v1/scans/$SCAN_ID/publish-ticket" \\\n  -H "Authorization: Bearer $SATRIA_TOKEN" \\\n  -H "Content-Type: application/json" \\\n  -d "{\\"target_system\\":\\"IRIS\\",\\"severity_filter\\":[\\"critical\\",\\"high\\"]}"'
                        },
                    ]},
                    {'title': 'Policy gate dan keputusan release', 'items': [
                        'Keputusan minimum yang perlu didukung adalah allowed, blocked, dan need_approval. Policy ini harus konsisten antara SATRIA, DevSecOps, dan approver perubahan.',
                        'Contoh kebijakan yang umum: blocked bila ada Critical, need_approval bila ada High di atas ambang tertentu, dan allowed bila hanya ada Medium atau Low yang masih dalam toleransi.',
                        'Kebijakan gate tidak harus murni berdasarkan jumlah temuan; organisasi dapat menambah parameter lain seperti jenis paket, exploitability, asset criticality, atau daftar pengecualian yang sah.',
                        'Jika release diblokir, pipeline wajib berhenti sebelum stage deploy production. Jika need_approval, pipeline masuk ke hold stage sambil menunggu approval atau risk acceptance yang terdokumentasi.',
                    ]},
                    {'title': 'Contoh konfigurasi Jenkins yang direkomendasikan', 'intro': [
                        'Bila organisasi memakai Jenkins, praktik yang disarankan adalah menyimpan token SATRIA di Jenkins Credentials, lalu memanggil API SATRIA dari stage terpisah setelah image berhasil dipush ke registry. Dengan cara ini, build dan security gate tetap terpisah secara jelas.'
                    ], 'items': [
                        'Buat credential bertipe Secret text di Jenkins, misalnya dengan ID satria-api-token, lalu simpan bearer token yang telah diberikan administrator SATRIA.',
                        'Tambahkan environment variable di Jenkinsfile untuk SATRIA_URL, SATRIA_TOKEN, SATRIA_ASSET_CODE, SATRIA_ASSET_NAME, dan REGISTRY_IMAGE.',
                        'Setelah stage build dan push selesai, buat file JSON intake dan scan-request, lalu panggil endpoint SATRIA menggunakan curl atau wrapper script bash/python.',
                        'Simpan scan_id sebagai artefak pipeline atau environment sementara agar bisa dipakai pada stage polling, gate, dan publish ticket.',
                        'Buat stage approval terpisah bila decision dari SATRIA bernilai need_approval, sehingga release tidak otomatis lanjut ke production.',
                    ], 'snippets': [
                        {
                            'title': 'Contoh Jenkinsfile sederhana',
                            'code': """pipeline {
  agent any
  environment {
    SATRIA_URL = "http://10.216.208.249:8090"
    SATRIA_TOKEN = credentials("satria-api-token")
    REGISTRY_IMAGE = "registry.internal/sakti-api:${BUILD_NUMBER}-${GIT_COMMIT.take(8)}"
    SATRIA_ASSET_CODE = "SAKTI-API"
    SATRIA_ASSET_NAME = "SAKTI API"
  }
  stages {
    stage("Build") {
      steps {
        sh "docker build -t ${REGISTRY_IMAGE} ."
      }
    }
    stage("Push") {
      steps {
        sh "docker push ${REGISTRY_IMAGE}"
      }
    }
    stage("Security Gate via SATRIA") {
      steps {
        sh \"\"\"
cat > release-intake.json <<EOF
{
  \\"asset_code\\": \\"${SATRIA_ASSET_CODE}\\",
  \\"asset_name\\": \\"${SATRIA_ASSET_NAME}\\",
  \\"release_version\\": \\"release-${BUILD_NUMBER}-${GIT_COMMIT:0:8}\\",
  \\"image_ref\\": \\"${REGISTRY_IMAGE}\\",
  \\"git_commit\\": \\"${GIT_COMMIT}\\",
  \\"build_number\\": \\"${BUILD_NUMBER}\\",
  \\"environment_target\\": \\"production\\"
}
EOF
RELEASE_RESPONSE=$(curl -s -X POST \\"$SATRIA_URL/api/v1/releases/intake\\" \\
  -H \\"Authorization: Bearer $SATRIA_TOKEN\\" \\
  -H \\"Content-Type: application/json\\" \\
  -d @release-intake.json)
echo "$RELEASE_RESPONSE" > release-response.json
ASSET_ID=$(python3 -c 'import json; print(json.load(open("release-response.json"))["asset_id"])')
RELEASE_ID=$(python3 -c 'import json; print(json.load(open("release-response.json"))["release_id"])')
cat > scan-request.json <<EOF
{
  \\"asset_id\\": ${ASSET_ID},
  \\"release_id\\": ${RELEASE_ID},
  \\"image_ref\\": \\"${REGISTRY_IMAGE}\\",
  \\"scan_profile\\": \\"quick_container\\",
  \\"requested_by\\": \\"jenkins\\",
  \\"build_number\\": \\"${BUILD_NUMBER}\\"
}
EOF
SCAN_RESPONSE=$(curl -s -X POST \\"$SATRIA_URL/api/v1/scans\\" \\
  -H \\"Authorization: Bearer $SATRIA_TOKEN\\" \\
  -H \\"Content-Type: application/json\\" \\
  -d @scan-request.json)
echo "$SCAN_RESPONSE" > scan-response.json
SCAN_ID=$(python3 -c 'import json; print(json.load(open("scan-response.json"))["scan_id"])')
echo "Scan job SATRIA berhasil dibuat: $SCAN_ID"
        \"\"\"
      }
    }
  }
}"""
                        },
                    ], 'note': 'Contoh di atas sudah mengambil asset_id dan release_id dari respons intake release. Pada implementasi produksi, pola ini lebih aman dibanding hardcode ID karena tetap konsisten walau aset baru ditambahkan atau dipetakan ulang.'},
                    {'title': 'Konfigurasi Jenkins di UI yang disarankan', 'items': [
                        'Masuk ke Jenkins sebagai administrator atau pengelola pipeline, lalu buka Manage Jenkins -> Credentials.',
                        'Tambahkan credential baru pada domain yang sesuai menggunakan jenis Secret text. Isi secret dengan token SATRIA dan gunakan ID yang mudah dikenali, misalnya satria-api-token.',
                        'Bila registry internal juga membutuhkan autentikasi, tambahkan credential registry secara terpisah agar build, push, dan scan tetap dapat ditelusuri dengan jelas.',
                        'Pada job pipeline, aktifkan parameter yang relevan seperti IMAGE_REF, ASSET_CODE, ASSET_NAME, SCAN_PROFILE, ENVIRONMENT_TARGET, dan PUBLISH_TO_IRIS bila pola organisasinya menghendaki fleksibilitas per release.',
                        'Jika organisasi menggunakan folder multibranch atau shared library, simpan fungsi pemanggil SATRIA sebagai shared step agar seluruh tim memakai pola integrasi yang sama.',
                    ], 'snippets': [
                        {
                            'title': 'Nilai parameter yang umum pada Jenkins job',
                            'code': 'IMAGE_REF=registry.internal/sakti-api:release-2026.07.04-201-a1b2c3d4\nASSET_CODE=SAKTI-API\nASSET_NAME=SAKTI API\nSCAN_PROFILE=quick_container\nENVIRONMENT_TARGET=production\nPUBLISH_TO_IRIS=false'
                        },
                        {
                            'title': 'Konvensi credential yang direkomendasikan',
                            'code': 'satria-api-token          -> Secret text\nregistry-internal-reader   -> Username with password / token\ngit-release-key            -> SSH key atau PAT untuk checkout'
                        },
                    ], 'note': 'Bila job akan dipakai oleh banyak aplikasi, gunakan parameter ASSET_CODE dan ASSET_NAME sebagai mandatory input agar setiap release tetap masuk ke aset SATRIA yang benar dan tidak tercampur.'},
                    {'title': 'Contoh Jenkins Configuration as Code dan YAML pendukung', 'intro': [
                        'Beberapa tim DevOps lebih nyaman mengelola Jenkins secara deklaratif. Contoh berikut dapat dipakai bila Jenkins dikelola dengan Jenkins Configuration as Code atau docker compose lokal untuk kebutuhan uji integrasi.'
                    ], 'items': [
                        'Tambahkan URL Jenkins dan konfigurasi credential secara deklaratif bila instans Jenkins dibangun ulang secara otomatis.',
                        'Pastikan plugin dasar seperti Configuration as Code, Credentials Binding, Pipeline, dan Plain Credentials sudah terpasang.',
                        'Simpan token SATRIA sebagai secret atau environment yang hanya diekspose ke Jenkins controller, lalu referensikan nilainya pada blok credentials.',
                    ], 'snippets': [
                        {
                            'title': 'Contoh docker-compose.yml Jenkins lokal',
                            'code': 'services:\n  jenkins:\n    build: .\n    container_name: jenkins-satria-local\n    ports:\n      - "8088:8080"\n    environment:\n      CASC_JENKINS_CONFIG: /var/jenkins_home/casc/jenkins.yaml\n      SATRIA_URL: http://host.docker.internal:8090\n      SATRIA_TOKEN: ${SATRIA_TOKEN}\n    volumes:\n      - jenkins_home:/var/jenkins_home\n      - ./casc:/var/jenkins_home/casc\n      - ./jobs:/var/jenkins_home/jobs'
                        },
                        {
                            'title': 'Contoh jenkins.yaml (JCasC) minimum',
                            'code': 'jenkins:\n  systemMessage: "Jenkins integrasi SATRIA"\ncredentials:\n  system:\n    domainCredentials:\n      - credentials:\n          - string:\n              id: "satria-api-token"\n              secret: "${SATRIA_TOKEN}"\n              scope: GLOBAL\n              description: "Bearer token integrasi SATRIA"'
                        },
                    ], 'note': 'Bila organisasi belum memakai JCasC, bagian ini tetap berguna sebagai referensi field apa saja yang perlu dimasukkan saat membangun Jenkins container atau saat menyiapkan bootstrap environment.'},
                    {'title': 'Contoh GitLab CI / YAML minimal', 'intro': [
                        'Untuk GitLab CI, prinsipnya sama: token SATRIA disimpan di CI/CD Variables dan dipanggil setelah image selesai dipush. Contoh berikut dapat dijadikan baseline awal lalu disesuaikan dengan runner dan registry internal yang digunakan.'
                    ], 'items': [
                        'Simpan SATRIA_TOKEN sebagai masked variable dan protected variable di GitLab.',
                        'Simpan SATRIA_URL, SATRIA_ASSET_CODE, dan SATRIA_ASSET_NAME sebagai CI variable level project atau group.',
                        'Pada job security_gate, gunakan curl untuk intake release, create scan, polling hasil, lalu set exit code job berdasarkan decision dari SATRIA.',
                    ], 'snippets': [
                        {
                            'title': 'Contoh .gitlab-ci.yml minimal',
                            'code': """stages:
  - build
  - push
  - security_gate

variables:
  SATRIA_URL: "http://10.216.208.249:8090"
  SATRIA_ASSET_CODE: "SAKTI-API"
  SATRIA_ASSET_NAME: "SAKTI API"

security_gate:
  stage: security_gate
  image: python:3.12-alpine
  before_script:
    - apk add --no-cache curl
  script:
    - export RELEASE_VERSION="release-${CI_PIPELINE_ID}-${CI_COMMIT_SHORT_SHA}"
    - export IMAGE_REF="${CI_REGISTRY_IMAGE}:${RELEASE_VERSION}"
    - |
      cat > release-intake.json <<EOF
      {
        "asset_code": "${SATRIA_ASSET_CODE}",
        "asset_name": "${SATRIA_ASSET_NAME}",
        "release_version": "${RELEASE_VERSION}",
        "image_ref": "${IMAGE_REF}",
        "git_commit": "${CI_COMMIT_SHA}",
        "build_number": "${CI_PIPELINE_ID}",
        "environment_target": "production"
      }
      EOF
    - curl -s -X POST "$SATRIA_URL/api/v1/releases/intake" -H "Authorization: Bearer $SATRIA_TOKEN" -H "Content-Type: application/json" -d @release-intake.json -o release-response.json
    - export ASSET_ID=$(python3 -c "import json; print(json.load(open('release-response.json'))['asset_id'])")
    - export RELEASE_ID=$(python3 -c "import json; print(json.load(open('release-response.json'))['release_id'])")
    - |
      cat > scan-request.json <<EOF
      {
        "asset_id": ${ASSET_ID},
        "release_id": ${RELEASE_ID},
        "image_ref": "${IMAGE_REF}",
        "scan_profile": "quick_container",
        "requested_by": "gitlab-ci",
        "build_number": "${CI_PIPELINE_ID}"
      }
      EOF
    - curl -s -X POST "$SATRIA_URL/api/v1/scans" -H "Authorization: Bearer $SATRIA_TOKEN" -H "Content-Type: application/json" -d @scan-request.json -o scan-response.json
    - export SCAN_ID=$(python3 -c "import json; print(json.load(open('scan-response.json'))['scan_id'])")
    - echo "Scan SATRIA terbentuk: ${SCAN_ID}"
    - echo "Lanjutkan dengan polling /api/v1/scans/${SCAN_ID} lalu evaluasi /result sebelum deploy"
"""
                        },
                    ], 'note': 'Jika organisasi memakai file pipeline lain seperti Helm values, Argo, atau Tekton, prinsip pemetaannya tetap sama: simpan token di secret manager, kirim metadata release yang konsisten, lalu baca decision dari SATRIA sebelum artefak dipromosikan.'},
                    {'title': 'Contoh stage gate dan logika keputusan pipeline', 'items': [
                        'Jika decision = allowed, stage gate selesai sukses dan pipeline dapat lanjut ke promote/deploy berikutnya.',
                        'Jika decision = blocked, pipeline harus berhenti dengan exit code non-zero dan release tidak boleh dipromosikan.',
                        'Jika decision = need_approval, pipeline masuk ke hold stage atau manual approval; status ini bukan sukses otomatis dan bukan gagal teknis.',
                        'Bila SATRIA mengembalikan failed, cancelled, timeout, atau error_code tertentu, pipeline menandai build sebagai failed atau unstable sesuai kebijakan DevSecOps.',
                    ], 'snippets': [
                        {
                            'title': 'Contoh pseudo-code evaluasi gate',
                            'code': 'if result.status != "completed":\n    fail_pipeline("scan belum selesai normal")\n\nif result.decision == "allowed":\n    continue_deploy()\nelif result.decision == "need_approval":\n    wait_manual_approval()\nelse:\n    fail_pipeline("release diblokir oleh SATRIA")'
                        },
                    ]},
                    {'title': 'Checklist implementasi sebelum dinyatakan siap produksi', 'items': [
                        'Service account SATRIA sudah aktif dan token tersimpan di Jenkins Credentials atau CI/CD Variables.',
                        'Registry internal dapat diakses dari server SATRIA dan image yang dipush pipeline dapat dipull ulang oleh worker SATRIA.',
                        'Aset pada SATRIA sudah terdaftar dengan asset_code yang sama seperti yang dipakai pipeline.',
                        'Profile scan yang digunakan pipeline sudah disetujui, misalnya quick_container untuk gate cepat atau full_container untuk release kritikal.',
                        'Policy gate, threshold severity, dan aturan publish ke IRIS sudah disepakati tertulis antara DevOps, SecOps, dan approver perubahan.',
                        'Smoke test integrasi minimal satu kali sudah berhasil: intake release sukses, scan sukses, result JSON terbaca, dan gate decision benar-benar memengaruhi hasil pipeline.',
                    ], 'snippets': [
                        {
                            'title': 'Acceptance criteria singkat',
                            'code': '1. Build dan push image berhasil\n2. SATRIA menerima intake release\n3. Scan job terbentuk otomatis\n4. Pipeline dapat membaca decision allowed/blocked/need_approval\n5. Release blocked benar-benar menghentikan promote\n6. Publish ke IRIS hanya dilakukan bila kebijakan menghendaki'
                        },
                    ], 'note': 'Dengan checklist ini, tim pengembang tidak hanya tahu cara memanggil API SATRIA, tetapi juga tahu indikator bahwa integrasi sudah layak dipakai sebagai security gate operasional.'},
                    {'title': 'Publish ticket ke IRIS dari pipeline atau operator', 'intro': [
                        'Tidak semua temuan harus langsung menjadi ticket IRIS. Praktik yang lebih aman adalah mempublish hanya temuan dengan severity tertentu, misalnya critical dan high, setelah hasil scan ditinjau cepat oleh tim yang berwenang.'
                    ], 'items': [
                        'Gunakan target_system = IRIS untuk kasus yang benar-benar harus masuk workflow resmi.',
                        'Gunakan severity_filter agar pipeline tidak membuat ticket berlebihan untuk semua temuan medium atau low.',
                        'Isi assign_to dan due_date bila organisasi sudah memiliki pemilik tindak lanjut yang jelas.',
                        'SATRIA akan menyimpan referensi nomor case/ticket agar statusnya tetap bisa dipantau dari halaman Tickets.',
                    ], 'snippets': [
                        {
                            'title': 'Contoh publish hanya temuan critical dan high',
                            'code': """curl -X POST "$SATRIA_URL/api/v1/scans/$SCAN_ID/publish-ticket" \\
  -H "Authorization: Bearer $SATRIA_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "target_system": "IRIS",
    "severity_filter": ["critical", "high"],
    "assign_to": "Tim Pengembang SAKTI",
    "due_date": "2026-07-31"
  }'"""
                        },
                    ]},
                    {'title': 'Error handling, audit trail, dan checklist implementasi', 'items': [
                        'Pipeline harus menerima error yang jelas jika image tidak valid, aset tidak dikenal, profile scan tidak tersedia, credential registry gagal, atau scan timeout. Semua kondisi ini harus memunculkan pesan yang mudah dibaca operator.',
                        'SATRIA perlu mencatat siapa yang meminta scan, kapan request dibuat, image dan digest yang diperiksa, profile scan yang digunakan, perubahan status job, serta keputusan gate yang dihasilkan.',
                        'Checklist minimum implementasi meliputi: service account pipeline aktif, konektivitas SATRIA ke registry berhasil, profile scan disetujui, endpoint integrasi tersedia, threshold gate disepakati, dan format hasil JSON sudah dapat dibaca pipeline.',
                        'Kondisi siap operasional dapat dinyatakan terpenuhi bila pipeline mampu membuat intake release, menjalankan scan otomatis, membaca hasil gate, menghentikan release yang tidak lolos, dan meneruskan temuan berat ke IRIS bila diperlukan.',
                    ], 'note': 'Sebelum masuk produksi, lakukan smoke test integrasi menggunakan satu image uji yang aman. Verifikasi bahwa SATRIA menerima intake release, membuat scan job, mengembalikan result JSON, dan memunculkan decision yang dapat dibaca pipeline tanpa interaksi manual melalui UI.'},
                ],
            },
        },
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


class ApiV1Error(Exception):
    def __init__(
        self,
        status_code: int,
        error_code: str,
        message: str,
        *,
        scan_id: int | None = None,
        details: dict | None = None,
    ) -> None:
        self.status_code = status_code
        self.error_code = error_code
        self.message = message
        self.scan_id = scan_id
        self.details = details or {}


def _safe_next_path(next_path: str | None) -> str:
    if not next_path or not next_path.startswith('/'):
        return '/'
    if next_path.startswith('//'):
        return '/'
    return next_path


def _raise_api_error(
    status_code: int,
    error_code: str,
    message: str,
    *,
    scan_id: int | None = None,
    details: dict | None = None,
) -> None:
    raise ApiV1Error(
        status_code=status_code,
        error_code=error_code,
        message=message,
        scan_id=scan_id,
        details=details,
    )


@app.exception_handler(ApiV1Error)
async def api_v1_error_handler(_: Request, exc: ApiV1Error):
    payload: dict[str, object] = {
        'error_code': exc.error_code,
        'message': exc.message,
    }
    if exc.scan_id is not None:
        payload['scan_id'] = exc.scan_id
    if exc.details:
        payload['details'] = exc.details
    return JSONResponse(status_code=exc.status_code, content=payload)


def _current_user_name(request: Request) -> str:
    return str(getattr(request.state, 'current_user', '') or '').strip()


def _is_admin_user(username: str | None) -> bool:
    normalized = (username or '').strip().lower()
    return normalized in ADMIN_USERS


def _require_admin_request(request: Request) -> str:
    current_user = _current_user_name(request)
    if not _is_admin_user(current_user):
        raise HTTPException(status_code=403, detail='admin access required')
    return current_user


def _normalize_service_account_name(value: str) -> str:
    normalized = re.sub(r'[^a-z0-9._-]+', '-', (value or '').strip().lower())
    return normalized.strip('-.')


def _normalize_scope_values(values: list[str] | tuple[str, ...] | set[str] | None) -> list[str]:
    normalized = {
        str(value).strip()
        for value in (values or [])
        if str(value).strip() in API_SCOPE_VALUES
    }
    return sorted(normalized)


def _setting_value(db: Session, key: str) -> str | None:
    row = db.get(AppSetting, key)
    if not row:
        return None
    value = (row.value or '').strip()
    return value or None


def _set_setting(db: Session, key: str, value: str | None, *, updated_by: str | None = None):
    row = db.get(AppSetting, key)
    normalized_value = (value or '').strip() or None
    if row:
        row.value = normalized_value
        row.updated_by = updated_by
        row.updated_at = datetime.utcnow()
        return row
    row = AppSetting(
        key=key,
        value=normalized_value,
        updated_by=updated_by,
        updated_at=datetime.utcnow(),
    )
    db.add(row)
    return row


def _parse_setting_bool(value: str | None, fallback: bool) -> bool:
    normalized = (value or '').strip().lower()
    if normalized in {'1', 'true', 'yes', 'on'}:
        return True
    if normalized in {'0', 'false', 'no', 'off'}:
        return False
    return fallback


def _parse_setting_int(value: str | None, fallback: int) -> int:
    try:
        return max(0, int((value or '').strip()))
    except (TypeError, ValueError):
        return fallback


def _gate_runtime_config(db: Session) -> dict[str, object]:
    settings = get_settings()
    policy_name = _setting_value(db, 'gate_policy_name') or settings.gate_policy_name
    high_decision = _normalize_gate_decision(
        _setting_value(db, 'gate_high_decision'),
        _normalize_gate_decision(settings.gate_high_decision, 'need_approval'),
    )
    medium_decision = _normalize_gate_decision(
        _setting_value(db, 'gate_medium_decision'),
        _normalize_gate_decision(settings.gate_medium_decision, 'allowed'),
    )
    low_decision = _normalize_gate_decision(
        _setting_value(db, 'gate_low_decision'),
        _normalize_gate_decision(settings.gate_low_decision, 'allowed'),
    )
    return {
        'gate_policy_name': policy_name,
        'gate_block_on_critical': _parse_setting_bool(
            _setting_value(db, 'gate_block_on_critical'),
            settings.gate_block_on_critical,
        ),
        'gate_high_threshold': _parse_setting_int(
            _setting_value(db, 'gate_high_threshold'),
            settings.gate_high_threshold,
        ),
        'gate_high_decision': high_decision,
        'gate_medium_threshold': _parse_setting_int(
            _setting_value(db, 'gate_medium_threshold'),
            settings.gate_medium_threshold,
        ),
        'gate_medium_decision': medium_decision,
        'gate_low_threshold': _parse_setting_int(
            _setting_value(db, 'gate_low_threshold'),
            settings.gate_low_threshold,
        ),
        'gate_low_decision': low_decision,
    }


def _gate_policy_page_context(
    request: Request,
    db: Session,
    *,
    page_status: str | None = None,
    page_message: str | None = None,
) -> dict:
    effective = _gate_runtime_config(db)
    stored_values = {key: _setting_value(db, key) for key in GATE_SETTING_KEYS}
    return {
        'request': request,
        'page_status': page_status,
        'page_message': page_message,
        'effective': effective,
        'stored_values': stored_values,
        'has_overrides': any(bool(value) for value in stored_values.values()),
        'decision_options': GATE_DECISION_OPTIONS,
    }


def _serialize_scope_values(values: list[str] | tuple[str, ...] | set[str] | None) -> str:
    return ','.join(_normalize_scope_values(values))


def _parse_scope_values(raw_value: str | None) -> set[str]:
    return {
        item.strip()
        for item in (raw_value or '').split(',')
        if item.strip()
    }


def _scope_labels(raw_value: str | None) -> list[str]:
    scope_map = {option['value']: option['label'] for option in API_SCOPE_OPTIONS}
    labels: list[str] = []
    for value in _normalize_scope_values(_parse_scope_values(raw_value)):
        labels.append(scope_map.get(value, value))
    return labels


def _hash_api_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def _mask_api_token(token: str) -> str:
    cleaned = (token or '').strip()
    if len(cleaned) <= 12:
        return cleaned
    return f'{cleaned[:6]}...{cleaned[-4:]}'


def _generate_api_token() -> str:
    return f"sat_{secrets.token_urlsafe(32)}"


def _service_account_rows(db: Session) -> list[dict]:
    accounts = (
        db.query(ServiceAccountCredential)
        .order_by(ServiceAccountCredential.created_at.desc(), ServiceAccountCredential.id.desc())
        .all()
    )
    rows: list[dict] = []
    for account in accounts:
        rows.append({
            'account': account,
            'scope_values': _normalize_scope_values(_parse_scope_values(account.scopes)),
            'scope_labels': _scope_labels(account.scopes),
        })
    return rows


def _service_account_page_context(
    request: Request,
    db: Session,
    *,
    page_status: str | None = None,
    page_message: str | None = None,
    token_value: str | None = None,
    token_label: str | None = None,
    token_message: str | None = None,
) -> dict:
    settings = get_settings()
    fallback_scopes = sorted(settings.api_scopes())
    return {
        'request': request,
        'accounts': _service_account_rows(db),
        'scope_options': API_SCOPE_OPTIONS,
        'page_status': page_status,
        'page_message': page_message,
        'token_value': token_value,
        'token_label': token_label,
        'token_message': token_message,
        'fallback_token_configured': bool((settings.satria_api_token or '').strip()),
        'fallback_service_account': settings.satria_api_service_account,
        'fallback_scopes': fallback_scopes,
    }


def _authorize_service_account(
    authorization: str | None,
    required_scope: str | None = None,
    *,
    db: Session | None = None,
) -> str:
    settings = get_settings()
    if not authorization or not authorization.startswith('Bearer '):
        _raise_api_error(401, 'API_AUTH_MISSING', 'Missing bearer token')

    provided_token = authorization.split(' ', 1)[1].strip()
    if not provided_token:
        _raise_api_error(401, 'API_AUTH_MISSING', 'Missing bearer token')

    if db is not None:
        credential = (
            db.query(ServiceAccountCredential)
            .filter(
                ServiceAccountCredential.is_active == True,  # noqa: E712
                ServiceAccountCredential.token_hash == _hash_api_token(provided_token),
            )
            .first()
        )
        if credential:
            scopes = _parse_scope_values(credential.scopes)
            if required_scope and required_scope not in scopes:
                _raise_api_error(
                    403,
                    'API_SCOPE_DENIED',
                    f'Service account does not have scope {required_scope}',
                    details={'required_scope': required_scope, 'service_account': credential.name},
                )
            return credential.name

    expected_token = (settings.satria_api_token or '').strip()
    if expected_token and secrets.compare_digest(provided_token, expected_token):
        if required_scope and required_scope not in settings.api_scopes():
            _raise_api_error(
                403,
                'API_SCOPE_DENIED',
                f'Service account does not have scope {required_scope}',
                details={'required_scope': required_scope, 'service_account': settings.satria_api_service_account},
            )
        return settings.satria_api_service_account

    has_db_credential = False
    if db is not None:
        has_db_credential = (
            db.query(ServiceAccountCredential.id)
            .filter(ServiceAccountCredential.is_active == True)  # noqa: E712
            .first()
            is not None
        )

    if not has_db_credential and not expected_token:
        _raise_api_error(503, 'API_AUTH_NOT_CONFIGURED', 'SATRIA API token is not configured')

    _raise_api_error(401, 'API_AUTH_INVALID', 'Invalid bearer token')


def _service_account_scope(required_scope: str):
    def dependency(
        authorization: str | None = Header(default=None),
        db: Session = Depends(get_db),
    ) -> str:
        return _authorize_service_account(authorization, required_scope, db=db)

    return dependency


def _severity_summary_for_scan(db: Session, scan_job_id: int) -> dict[str, int]:
    rows = (
        db.query(Finding.severity_normalized, func.count(Finding.id))
        .filter(Finding.scan_job_id == scan_job_id)
        .group_by(Finding.severity_normalized)
        .all()
    )
    summary = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'informational': 0,
        'total': 0,
    }
    for severity, count in rows:
        normalized = (severity or 'Informational').lower()
        if normalized == 'critical':
            summary['critical'] += int(count)
        elif normalized == 'high':
            summary['high'] += int(count)
        elif normalized == 'medium':
            summary['medium'] += int(count)
        elif normalized == 'low':
            summary['low'] += int(count)
        else:
            summary['informational'] += int(count)
        summary['total'] += int(count)
    return summary


def _normalize_gate_decision(value: str | None, fallback: str) -> str:
    normalized = (value or '').strip().lower()
    if normalized in {'allowed', 'need_approval', 'blocked', 'pending'}:
        return normalized
    return fallback


def _release_metadata(scan: ScanJob) -> dict[str, object]:
    if not scan.release or not scan.release.metadata_json:
        return {}
    try:
        parsed = json.loads(scan.release.metadata_json)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        return {}
    return {}


def _gate_decision_for_scan(scan: ScanJob, severity_summary: dict[str, int], db: Session) -> str:
    gate_config = _gate_runtime_config(db)
    if scan.status in {'queued', 'running'}:
        return 'pending'
    if scan.status != 'completed':
        return 'blocked'
    release_metadata = _release_metadata(scan)
    override_decision = _normalize_gate_decision(
        str(release_metadata.get('gate_override_decision') or ''),
        '',
    )
    if override_decision:
        return override_decision
    if gate_config['gate_block_on_critical'] and severity_summary.get('critical', 0) > 0:
        return 'blocked'
    if gate_config['gate_high_threshold'] > 0 and severity_summary.get('high', 0) >= gate_config['gate_high_threshold']:
        return _normalize_gate_decision(str(gate_config['gate_high_decision']), 'need_approval')
    if gate_config['gate_medium_threshold'] > 0 and severity_summary.get('medium', 0) >= gate_config['gate_medium_threshold']:
        return _normalize_gate_decision(str(gate_config['gate_medium_decision']), 'allowed')
    if gate_config['gate_low_threshold'] > 0 and severity_summary.get('low', 0) >= gate_config['gate_low_threshold']:
        return _normalize_gate_decision(str(gate_config['gate_low_decision']), 'allowed')
    return 'allowed'


def _pipeline_status_payload(scan: ScanJob, db: Session) -> dict:
    severity_summary = _severity_summary_for_scan(db, scan.id)
    gate_decision = _gate_decision_for_scan(scan, severity_summary, db)
    requested_by = scan.release.requested_by if scan.release else None
    build_number = scan.release.build_number if scan.release else None
    return {
        'scan_id': scan.id,
        'asset_id': scan.asset_id,
        'asset_name': scan.asset.name if scan.asset else f'asset-{scan.asset_id}',
        'release_id': scan.release_id,
        'profile': scan.profile,
        'scanner': scan.scanner,
        'status': scan.status,
        'gate_decision': gate_decision,
        'requested_by': requested_by,
        'build_number': build_number,
        'created_at': scan.created_at,
        'started_at': scan.started_at,
        'completed_at': scan.completed_at,
        'message': scan.message,
        'severity_summary': severity_summary,
    }


def _pipeline_result_payload(scan: ScanJob, db: Session) -> dict:
    status_payload = _pipeline_status_payload(scan, db)
    mode_label, _ = _scan_mode(scan)
    release_metadata = _release_metadata(scan)
    gate_config = _gate_runtime_config(db)
    return {
        **status_payload,
        'mode': mode_label.lower().replace(' ', '_'),
        'decision': status_payload['gate_decision'],
        'policy_name': str(gate_config['gate_policy_name']),
        'total_findings': status_payload['severity_summary']['total'],
        'report_path': scan.raw_report_path,
        'report_url': f'/scans/{scan.id}',
        'finding_url': f'/findings?scan_job_id={scan.id}',
        'publish_ticket_url': f'/api/v1/scans/{scan.id}/publish-ticket',
        'risk_acceptance_ref': release_metadata.get('risk_acceptance_ref'),
    }


@app.middleware('http')
async def require_login(request: Request, call_next):
    request.state.current_user = request.cookies.get('satria_user')
    request.state.is_admin = _is_admin_user(request.state.current_user)
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


@app.get('/admin/service-accounts', response_class=HTMLResponse)
def service_accounts_page(
    request: Request,
    status: str | None = None,
    message: str | None = None,
    db: Session = Depends(get_db),
):
    _require_admin_request(request)
    return templates.TemplateResponse(
        'service_accounts.html',
        _service_account_page_context(
            request,
            db,
            page_status=(status or '').strip() or None,
            page_message=(message or '').strip() or None,
        ),
    )


@app.get('/admin/gate-policy', response_class=HTMLResponse)
def gate_policy_page(
    request: Request,
    status: str | None = None,
    message: str | None = None,
    db: Session = Depends(get_db),
):
    _require_admin_request(request)
    return templates.TemplateResponse(
        'gate_policy.html',
        _gate_policy_page_context(
            request,
            db,
            page_status=(status or '').strip() or None,
            page_message=(message or '').strip() or None,
        ),
    )


@app.post('/admin/gate-policy', response_class=HTMLResponse)
def save_gate_policy(
    request: Request,
    gate_policy_name: str = Form(''),
    gate_block_on_critical: str | None = Form(None),
    gate_high_threshold: int = Form(0),
    gate_high_decision: str = Form('need_approval'),
    gate_medium_threshold: int = Form(0),
    gate_medium_decision: str = Form('allowed'),
    gate_low_threshold: int = Form(0),
    gate_low_decision: str = Form('allowed'),
    db: Session = Depends(get_db),
):
    admin_user = _require_admin_request(request)

    def _clean_threshold(value: int) -> int:
        return max(0, int(value))

    decision_values = {
        'gate_high_decision': gate_high_decision,
        'gate_medium_decision': gate_medium_decision,
        'gate_low_decision': gate_low_decision,
    }
    invalid_decision = next((key for key, value in decision_values.items() if value not in GATE_DECISION_VALUES), None)
    if invalid_decision:
        return templates.TemplateResponse(
            'gate_policy.html',
            _gate_policy_page_context(
                request,
                db,
                page_status='error',
                page_message='Keputusan gate tidak valid. Pilih Allowed, Need Approval, atau Blocked.',
            ),
            status_code=400,
        )

    _set_setting(db, 'gate_policy_name', (gate_policy_name or '').strip(), updated_by=admin_user)
    _set_setting(db, 'gate_block_on_critical', 'true' if gate_block_on_critical else 'false', updated_by=admin_user)
    _set_setting(db, 'gate_high_threshold', str(_clean_threshold(gate_high_threshold)), updated_by=admin_user)
    _set_setting(db, 'gate_high_decision', gate_high_decision, updated_by=admin_user)
    _set_setting(db, 'gate_medium_threshold', str(_clean_threshold(gate_medium_threshold)), updated_by=admin_user)
    _set_setting(db, 'gate_medium_decision', gate_medium_decision, updated_by=admin_user)
    _set_setting(db, 'gate_low_threshold', str(_clean_threshold(gate_low_threshold)), updated_by=admin_user)
    _set_setting(db, 'gate_low_decision', gate_low_decision, updated_by=admin_user)
    db.add(AuditLog(
        actor=admin_user,
        action='gate_policy_updated',
        object_type='app_setting',
        object_id='gate_policy',
        detail=(
            f'policy={gate_policy_name}; block_critical={bool(gate_block_on_critical)}; '
            f'high={gate_high_threshold}:{gate_high_decision}; '
            f'medium={gate_medium_threshold}:{gate_medium_decision}; '
            f'low={gate_low_threshold}:{gate_low_decision}'
        ),
    ))
    db.commit()
    return templates.TemplateResponse(
        'gate_policy.html',
        _gate_policy_page_context(
            request,
            db,
            page_status='success',
            page_message='Gate policy berhasil diperbarui. Evaluasi pipeline baru akan memakai konfigurasi ini.',
        ),
    )


@app.post('/admin/service-accounts', response_class=HTMLResponse)
def create_service_account(
    request: Request,
    name: str = Form(...),
    display_name: str = Form(''),
    description: str = Form(''),
    scopes: list[str] = Form([]),
    db: Session = Depends(get_db),
):
    admin_user = _require_admin_request(request)
    normalized_name = _normalize_service_account_name(name)
    normalized_scopes = _normalize_scope_values(scopes)

    if not normalized_name:
        return templates.TemplateResponse(
            'service_accounts.html',
            _service_account_page_context(
                request,
                db,
                page_status='error',
                page_message='Nama service account belum valid. Gunakan huruf, angka, titik, strip, atau underscore.',
            ),
            status_code=400,
        )

    if not normalized_scopes:
        return templates.TemplateResponse(
            'service_accounts.html',
            _service_account_page_context(
                request,
                db,
                page_status='error',
                page_message='Pilih minimal satu scope API untuk service account ini.',
            ),
            status_code=400,
        )

    existing = (
        db.query(ServiceAccountCredential)
        .filter(ServiceAccountCredential.name == normalized_name)
        .first()
    )
    if existing:
        return templates.TemplateResponse(
            'service_accounts.html',
            _service_account_page_context(
                request,
                db,
                page_status='error',
                page_message=f'Service account {normalized_name} sudah ada. Gunakan nama lain atau rotasi token akun yang sudah ada.',
            ),
            status_code=409,
        )

    token_value = _generate_api_token()
    account = ServiceAccountCredential(
        name=normalized_name,
        display_name=(display_name or '').strip() or normalized_name,
        description=(description or '').strip() or None,
        scopes=_serialize_scope_values(normalized_scopes),
        token_hash=_hash_api_token(token_value),
        token_hint=_mask_api_token(token_value),
        is_active=True,
        created_by=admin_user,
        last_rotated_at=datetime.utcnow(),
    )
    db.add(account)
    db.flush()
    db.add(AuditLog(
        actor=admin_user,
        action='service_account_created',
        object_type='service_account_credential',
        object_id=str(account.id),
        detail=f'name={account.name}; scopes={account.scopes}',
    ))
    db.commit()
    return templates.TemplateResponse(
        'service_accounts.html',
        _service_account_page_context(
            request,
            db,
            page_status='success',
            page_message=f'Service account {account.name} berhasil dibuat.',
            token_value=token_value,
            token_label=f'Token baru untuk {account.name}',
            token_message='Salin token ini sekarang juga. Demi keamanan, nilai token hanya ditampilkan sekali saat dibuat atau dirotasi.',
        ),
    )


@app.post('/admin/service-accounts/{service_account_id}/rotate', response_class=HTMLResponse)
def rotate_service_account_token(
    service_account_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    admin_user = _require_admin_request(request)
    account = db.get(ServiceAccountCredential, service_account_id)
    if not account:
        raise HTTPException(status_code=404, detail='service account not found')

    token_value = _generate_api_token()
    account.token_hash = _hash_api_token(token_value)
    account.token_hint = _mask_api_token(token_value)
    account.last_rotated_at = datetime.utcnow()
    account.updated_at = datetime.utcnow()
    db.add(AuditLog(
        actor=admin_user,
        action='service_account_rotated',
        object_type='service_account_credential',
        object_id=str(account.id),
        detail=f'name={account.name}',
    ))
    db.commit()
    return templates.TemplateResponse(
        'service_accounts.html',
        _service_account_page_context(
            request,
            db,
            page_status='success',
            page_message=f'Token untuk {account.name} berhasil dirotasi.',
            token_value=token_value,
            token_label=f'Token hasil rotasi untuk {account.name}',
            token_message='Perbarui secret pada Jenkins, GitLab CI, atau secret manager lain sebelum pipeline dijalankan ulang.',
        ),
    )


@app.post('/admin/service-accounts/{service_account_id}/toggle')
def toggle_service_account_status(
    service_account_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    admin_user = _require_admin_request(request)
    account = db.get(ServiceAccountCredential, service_account_id)
    if not account:
        raise HTTPException(status_code=404, detail='service account not found')

    account.is_active = not account.is_active
    account.updated_at = datetime.utcnow()
    action = 'service_account_activated' if account.is_active else 'service_account_deactivated'
    status_label = 'diaktifkan' if account.is_active else 'dinonaktifkan'
    db.add(AuditLog(
        actor=admin_user,
        action=action,
        object_type='service_account_credential',
        object_id=str(account.id),
        detail=f'name={account.name}',
    ))
    db.commit()
    return RedirectResponse(
        url=f"/admin/service-accounts?status=success&message={quote_plus(f'Service account {account.name} berhasil {status_label}.')}",
        status_code=303,
    )


@app.post('/admin/service-accounts/{service_account_id}/delete')
def delete_service_account(
    service_account_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    admin_user = _require_admin_request(request)
    account = db.get(ServiceAccountCredential, service_account_id)
    if not account:
        raise HTTPException(status_code=404, detail='service account not found')

    account_name = account.name
    db.add(AuditLog(
        actor=admin_user,
        action='service_account_deleted',
        object_type='service_account_credential',
        object_id=str(account.id),
        detail=f'name={account_name}; scopes={account.scopes}',
    ))
    db.delete(account)
    db.commit()
    return RedirectResponse(
        url=f"/admin/service-accounts?status=success&message={quote_plus(f'Service account {account_name} berhasil dihapus.')}",
        status_code=303,
    )

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
    bulk_iris_candidates = bulk_critical_high_candidates_query(db).count()
    return templates.TemplateResponse('vulnerability_summary.html', {
        'request': request,
        'summary': summary,
        'bulk_iris_candidates': bulk_iris_candidates,
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


def bulk_critical_high_candidates_query(db: Session):
    return active_findings_query(db).filter(
        Finding.severity_normalized.in_(['Critical', 'High']),
        Finding.status.notin_(['Closed', 'False Positive', 'Accepted Risk']),
        Finding.ticket_case == None,  # noqa: E711
    )

@app.get('/assets', response_class=HTMLResponse)
def assets_page(
    request: Request,
    cleanup_status: str | None = None,
    cleanup_message: str | None = None,
    allowlist_status: str | None = None,
    allowlist_message: str | None = None,
    edit_id: int | None = None,
    db: Session = Depends(get_db),
):
    assets = db.query(Asset).filter(Asset.is_active == True).order_by(Asset.id.desc()).all()  # noqa: E712
    edit_asset = None
    if edit_id is not None:
        candidate = db.get(Asset, edit_id)
        if candidate and candidate.is_active:
            edit_asset = candidate
    return templates.TemplateResponse('assets.html', {
        'request': request,
        'assets': assets,
        'summary': get_summary(db),
        'cleanup_status': cleanup_status,
        'cleanup_message': cleanup_message,
        'allowlist_status': allowlist_status,
        'allowlist_message': allowlist_message,
        'allowlist_entries': database_allowlist_entries(db),
        'config_allowlist': configured_allowlist_rules(),
        'edit_asset': edit_asset,
    })


@app.get('/asset-sop', response_class=HTMLResponse)
def asset_sop_page(request: Request, asset_type: str = 'container_image', guide: str = 'default'):
    selected_asset_type = asset_type if asset_type in ASSET_TYPE_META else 'container_image'
    selected_asset_meta = ASSET_TYPE_META[selected_asset_type]
    sub_guides = selected_asset_meta.get('sub_guides', {})
    selected_guide_key = guide if guide in sub_guides else 'default'
    selected_guide = sub_guides[selected_guide_key] if selected_guide_key != 'default' else selected_asset_meta
    return templates.TemplateResponse('asset_sop.html', {
        'request': request,
        'asset_type_order': ASSET_TYPE_ORDER,
        'asset_type_meta': ASSET_TYPE_META,
        'selected_asset_type': selected_asset_type,
        'selected_guide': selected_guide,
        'selected_guide_key': selected_guide_key,
        'selected_asset_meta': selected_asset_meta,
        'asset_sub_guides': sub_guides,
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


@app.post('/assets/{asset_id}/edit')
def update_asset_form(
    asset_id: int,
    name: str = Form(...),
    asset_type: str = Form(...),
    target: str = Form(...),
    environment: str = Form('development'),
    criticality: str = Form('medium'),
    owner: str = Form(''),
    technical_pic: str = Form(''),
    db: Session = Depends(get_db),
):
    asset = db.get(Asset, asset_id)
    if not asset or not asset.is_active:
        raise HTTPException(status_code=404, detail='asset not found')

    asset.name = name
    asset.asset_type = asset_type
    asset.target = target
    asset.environment = environment
    asset.criticality = criticality
    asset.owner = owner or None
    asset.technical_pic = technical_pic or None

    db.add(AuditLog(
        action='asset_updated',
        object_type='asset',
        object_id=str(asset.id),
        detail=name,
    ))
    db.commit()
    return RedirectResponse('/assets', status_code=303)


@app.post('/allowlist')
def create_allowlist_entry(
    rule: str = Form(...),
    description: str = Form(''),
    db: Session = Depends(get_db),
):
    normalized_rule = (rule or '').strip()
    if not normalized_rule:
        return RedirectResponse(
            '/assets?allowlist_status=error&allowlist_message=Rule%20allowlist%20wajib%20diisi',
            status_code=303,
        )

    existing = (
        db.query(ScanAllowlistEntry)
        .filter(func.lower(ScanAllowlistEntry.rule) == normalized_rule.lower())
        .first()
    )
    if existing:
        existing.description = (description or '').strip() or existing.description
        existing.is_active = True
        db.add(AuditLog(
            action='allowlist_reactivated',
            object_type='scan_allowlist',
            object_id=str(existing.id),
            detail=normalized_rule,
        ))
        db.commit()
        return RedirectResponse(
            '/assets?allowlist_status=updated&allowlist_message=Rule%20allowlist%20diaktifkan%20atau%20diperbarui',
            status_code=303,
        )

    entry = ScanAllowlistEntry(
        rule=normalized_rule,
        description=(description or '').strip() or None,
        is_active=True,
    )
    db.add(entry)
    db.add(AuditLog(
        action='allowlist_created',
        object_type='scan_allowlist',
        detail=normalized_rule,
    ))
    db.commit()
    return RedirectResponse(
        '/assets?allowlist_status=ok&allowlist_message=Rule%20allowlist%20berhasil%20ditambahkan',
        status_code=303,
    )


@app.post('/allowlist/{entry_id}/delete')
def delete_allowlist_entry(entry_id: int, db: Session = Depends(get_db)):
    entry = db.get(ScanAllowlistEntry, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail='allowlist entry not found')

    db.add(AuditLog(
        action='allowlist_deleted',
        object_type='scan_allowlist',
        object_id=str(entry.id),
        detail=entry.rule,
    ))
    db.delete(entry)
    db.commit()
    return RedirectResponse(
        '/assets?allowlist_status=deleted&allowlist_message=Rule%20allowlist%20berhasil%20dihapus',
        status_code=303,
    )


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
def tickets_page(
    request: Request,
    db: Session = Depends(get_db),
    status: str | None = None,
    case_kind: str | None = None,
    remote_state: str | None = None,
):
    remote_cases = list_remote_cases()
    imported = import_remote_cases_to_satria(db, remote_cases) if remote_cases else 0
    if imported:
        db.commit()

    q = db.query(TicketCase)
    if case_kind:
        q = q.filter(TicketCase.case_kind == case_kind)
    tickets = q.order_by(TicketCase.updated_at.desc(), TicketCase.id.desc()).limit(300).all()
    remote_case_map = {
        str(case.get('case_id')): case
        for case in remote_cases
        if case.get('case_id') is not None
    }
    monitored_tickets = []
    ticket_views: dict[int, dict] = {}
    for ticket in tickets:
        remote = remote_case_map.get(str(ticket.remote_case_id))
        if remote_cases and ticket.remote_case_id and not remote:
            continue
        ticket_view = _ticket_case_view(ticket, remote)
        ticket_views[ticket.id] = ticket_view
        if status and ticket.status != status:
            continue
        if remote_state and ticket_view.get('remote_state') != remote_state:
            continue
        monitored_tickets.append(ticket)

    iris_state_order = ['Open', 'Assigned', 'In Progress', 'Remediated', 'Retest', 'Closed', 'False Positive', 'Accepted Risk']
    iris_state_colors = {
        'Open': '#4f5ed9',
        'Assigned': '#7c3aed',
        'In Progress': '#f28a30',
        'Remediated': '#4fb8a7',
        'Retest': '#f5cc42',
        'Closed': '#5ec865',
        'False Positive': '#94a3b8',
        'Accepted Risk': '#64748b',
    }
    iris_state_counts: dict[str, int] = {key: 0 for key in iris_state_order}
    for ticket in monitored_tickets:
        state = ticket_views[ticket.id].get('remote_state') or 'Unknown'
        if state not in iris_state_counts:
            iris_state_counts[state] = 0
        iris_state_counts[state] += 1
    iris_state_pie_segments = count_pie_segments(
        iris_state_counts,
        iris_state_order + [key for key in iris_state_counts.keys() if key not in iris_state_order],
        iris_state_colors,
        lambda key: f"/tickets?remote_state={quote_plus(key)}" + (f"&status={quote_plus(status)}" if status else "") + (f"&case_kind={quote_plus(case_kind)}" if case_kind else ""),
    )
    iris_state_pie_style = count_pie_style(
        iris_state_counts,
        iris_state_order + [key for key in iris_state_counts.keys() if key not in iris_state_order],
        iris_state_colors,
    )
    iris_state_total = sum(iris_state_counts.values())
    iris_state_primary = next((key for key in iris_state_order if iris_state_counts.get(key, 0) > 0), 'Open')
    ticket_summary = {
        'total': len(monitored_tickets),
        'finding': sum(1 for ticket in monitored_tickets if ticket.case_kind == 'finding'),
        'manual': sum(1 for ticket in monitored_tickets if ticket.case_kind == 'manual'),
        'synced': sum(1 for ticket in monitored_tickets if ticket.remote_case_id and ticket.last_sync_status in {'synced', 'monitored', 'partial-synced'}),
        'pending': sum(1 for ticket in monitored_tickets if not ticket.remote_case_id or ticket.last_sync_status not in {'synced', 'monitored', 'partial-synced'}),
    }
    return templates.TemplateResponse('tickets.html', {
        'request': request,
        'tickets': monitored_tickets,
        'ticket_views': ticket_views,
        'remote_case_map': remote_case_map,
        'iris_login_url': _iris_login_url(),
        'summary': get_summary(db),
        'ticket_summary': ticket_summary,
        'iris_state_counts': iris_state_counts,
        'iris_state_pie_segments': iris_state_pie_segments,
        'iris_state_pie_style': iris_state_pie_style,
        'iris_state_total': iris_state_total,
        'iris_state_primary': iris_state_primary,
        'status_filter': status,
        'case_kind_filter': case_kind,
        'remote_state_filter': remote_state,
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
    db.add(AuditLog(
        action='finding_status_update_blocked',
        object_type='finding',
        object_id=str(finding.id),
        detail=f'requested={status}',
    ))
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
    remote_cases = list_remote_cases()
    imported = import_remote_cases_to_satria(db, remote_cases) if remote_cases else 0
    tickets = db.query(TicketCase).filter(TicketCase.remote_case_id.is_not(None)).all()
    refreshed = 0
    for ticket in tickets:
        refresh_ticket_case_from_iris(ticket)
        refreshed += 1
    db.add(AuditLog(action='tickets_monitored_from_iris', object_type='ticket_case', detail=f'refreshed={refreshed}; imported={imported}'))
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
    findings = bulk_critical_high_candidates_query(db).order_by(Finding.risk_score.desc()).limit(100).all()
    sent = 0
    for finding in findings:
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

@app.post('/api/v1/releases/intake', response_model=ReleaseIntakeOut)
def api_v1_release_intake(
    payload: ReleaseIntakeCreate,
    service_account: str = Depends(_service_account_scope('release:write')),
    db: Session = Depends(get_db),
):
    asset = db.get(Asset, payload.asset_id) if payload.asset_id else None
    if not asset:
        asset = (
            db.query(Asset)
            .filter(
                Asset.name == payload.asset_name,
                Asset.asset_type == payload.asset_type,
            )
            .one_or_none()
        )
    if not asset:
        asset = Asset(
            name=payload.asset_name,
            asset_type=payload.asset_type,
            target=payload.target or payload.image_ref,
            environment=payload.environment,
            criticality=payload.criticality,
            owner=payload.owner,
            technical_pic=payload.technical_pic,
        )
        db.add(asset)
        db.flush()
    else:
        asset.target = payload.target or payload.image_ref
        asset.environment = payload.environment
        asset.criticality = payload.criticality
        if payload.owner:
            asset.owner = payload.owner
        if payload.technical_pic:
            asset.technical_pic = payload.technical_pic

    release = ReleaseArtifact(
        asset_id=asset.id,
        asset_code=payload.asset_code,
        release_version=payload.release_version,
        image_ref=payload.image_ref,
        image_digest=payload.image_digest,
        git_commit=payload.git_commit,
        build_number=payload.build_number,
        requested_by=payload.requested_by or service_account,
        environment_target=payload.environment_target or payload.environment,
        source_registry=payload.source_registry,
        metadata_json=json.dumps({
            **(payload.metadata or {}),
            **({'risk_acceptance_ref': payload.risk_acceptance_ref} if payload.risk_acceptance_ref else {}),
            **({'gate_override_decision': payload.gate_override_decision} if payload.gate_override_decision else {}),
        }, ensure_ascii=True),
    )
    db.add(release)
    db.add(AuditLog(
        actor=service_account,
        action='release_intake_v1',
        object_type='release_artifact',
        detail=f"{payload.asset_name}|{payload.release_version or '-'}|{payload.image_ref}",
    ))
    db.commit()
    db.refresh(release)
    return {
        'asset_id': asset.id,
        'release_id': release.id,
        'asset_name': asset.name,
        'asset_code': release.asset_code,
        'release_version': release.release_version,
        'image_ref': release.image_ref,
        'image_digest': release.image_digest,
        'git_commit': release.git_commit,
        'build_number': release.build_number,
        'requested_by': release.requested_by,
        'environment_target': release.environment_target,
        'risk_acceptance_ref': payload.risk_acceptance_ref,
        'gate_override_decision': payload.gate_override_decision,
        'created_at': release.created_at,
    }


@app.post('/api/v1/scans', response_model=PipelineScanStatusOut)
def api_v1_create_scan(
    payload: PipelineScanCreate,
    service_account: str = Depends(_service_account_scope('scan:create')),
    db: Session = Depends(get_db),
):
    release = db.get(ReleaseArtifact, payload.release_id) if payload.release_id else None
    asset = db.get(Asset, payload.asset_id) if payload.asset_id else None
    if not asset and release:
        asset = release.asset
    if not asset:
        _raise_api_error(404, 'ASSET_NOT_FOUND', 'asset not found')
    if payload.profile not in SUPPORTED_PROFILES:
        _raise_api_error(
            400,
            'SCAN_PROFILE_UNSUPPORTED',
            'unsupported scan profile',
            details={'supported_profiles': sorted(SUPPORTED_PROFILES)},
        )
    if payload.image_ref and release:
        registered_refs = {release.image_ref, asset.target}
        if release.image_digest:
            registered_refs.add(release.image_digest)
        if payload.image_ref not in registered_refs:
            _raise_api_error(
                400,
                'RELEASE_IMAGE_MISMATCH',
                'image_ref does not match registered release',
                details={'registered_refs': sorted(registered_refs)},
            )

    job = ScanJob(
        asset_id=asset.id,
        release_id=release.id if release else None,
        profile=payload.profile,
        scanner='+'.join(scanners_for_profile(payload.profile)),
        status='queued',
    )
    db.add(job)
    db.add(AuditLog(
        actor=service_account,
        action='scan_created_v1',
        object_type='scan_job',
        detail=f"{asset.name}/{payload.profile}/release={release.id if release else '-'}",
    ))
    db.commit()
    db.refresh(job)
    run_scan_job.delay(job.id)
    return _pipeline_status_payload(job, db)


@app.get('/api/v1/scans/{scan_id}', response_model=PipelineScanStatusOut)
def api_v1_scan_status(
    scan_id: int,
    service_account: str = Depends(_service_account_scope('scan:read')),
    db: Session = Depends(get_db),
):
    scan = db.get(ScanJob, scan_id)
    if not scan:
        _raise_api_error(404, 'SCAN_NOT_FOUND', 'scan not found', scan_id=scan_id)
    return _pipeline_status_payload(scan, db)


@app.get('/api/v1/scans/{scan_id}/result', response_model=PipelineScanResultOut)
def api_v1_scan_result(
    scan_id: int,
    service_account: str = Depends(_service_account_scope('scan:read')),
    db: Session = Depends(get_db),
):
    scan = db.get(ScanJob, scan_id)
    if not scan:
        _raise_api_error(404, 'SCAN_NOT_FOUND', 'scan not found', scan_id=scan_id)
    return _pipeline_result_payload(scan, db)


@app.post('/api/v1/scans/{scan_id}/publish-ticket', response_model=PipelinePublishTicketOut)
def api_v1_publish_ticket(
    scan_id: int,
    payload: PipelinePublishTicketRequest,
    service_account: str = Depends(_service_account_scope('ticket:publish')),
    db: Session = Depends(get_db),
):
    scan = db.get(ScanJob, scan_id)
    if not scan:
        _raise_api_error(404, 'SCAN_NOT_FOUND', 'scan not found', scan_id=scan_id)
    if scan.status != 'completed':
        _raise_api_error(409, 'SCAN_NOT_COMPLETED', 'scan is not completed', scan_id=scan_id)
    if payload.target_system.lower() != 'iris':
        _raise_api_error(
            400,
            'TARGET_SYSTEM_UNSUPPORTED',
            'target_system is not supported',
            scan_id=scan_id,
            details={'supported_target_systems': ['iris']},
        )

    severity_filter = payload.severity_filter or ['Critical', 'High']
    normalized_filter = {item.strip().title() for item in severity_filter if item.strip()}
    if not normalized_filter:
        normalized_filter = {'Critical', 'High'}

    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_job_id == scan.id,
            Finding.severity_normalized.in_(sorted(normalized_filter)),
        )
        .order_by(Finding.risk_score.desc(), Finding.id.desc())
        .all()
    )
    remote_ids: list[str] = []
    for finding in findings:
        remote_ids.append(send_finding_to_iris(db, finding, finding.asset))
    db.add(AuditLog(
        actor=service_account,
        action='scan_publish_ticket_v1',
        object_type='scan_job',
        object_id=str(scan.id),
        detail=(
            f'published={len(remote_ids)}'
            f'|target_system={payload.target_system}'
            f'|severity={",".join(sorted(normalized_filter))}'
            f'|assign_to={payload.assign_to or "-"}'
            f'|due_date={payload.due_date.isoformat() if payload.due_date else "-"}'
        ),
    ))
    db.commit()
    return {
        'scan_id': scan.id,
        'published_count': len(remote_ids),
        'remote_ids': remote_ids,
        'status': 'published' if remote_ids else 'no_critical_high_findings',
    }


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
    remote_state = (
        (remote_case or {}).get('state_name')
        or (remote_case or {}).get('status_name')
        or (remote_case or {}).get('case_state')
        or (remote_case or {}).get('state')
    )
    if not remote_state:
        if ticket.remote_case_id:
            remote_state = ticket.status or 'Open'
        else:
            remote_state = '-'
    elif remote_state != '-':
        remote_state = str(remote_state).replace('In progress', 'In Progress')
    return {
        'classification': (remote_case or {}).get('classification') or classification_label_for_case(ticket),
        'soc_id': (remote_case or {}).get('case_soc_id') or ticket.remote_case_soc_id or default_soc_id_for_case(ticket),
        'customer': (remote_case or {}).get('client_name') or (remote_case or {}).get('customer_name') or settings.iris_customer_name,
        'tags': tags_for_case(ticket),
        'workflow_status': ticket.status,
        'remote_state': remote_state,
        'remote_owner': (remote_case or {}).get('owner') or ticket.current_owner or '-',
        'remote_open_date': (remote_case or {}).get('case_open_date') or (remote_case or {}).get('open_date') or '-',
        'remote_name': (remote_case or {}).get('case_name') or ticket.remote_case_name or ticket.title,
    }


def _iris_login_url() -> str | None:
    settings = get_settings()
    if not settings.iris_url:
        return None
    return f"{settings.iris_url.rstrip('/')}/login"
