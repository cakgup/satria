# Skenario Pengembangan Jenkins ke SATRIA

Dokumen ini menjelaskan skenario uji pengembangan agar tim dapat mensimulasikan alur CI/CD yang terhubung ke SATRIA sebelum implementasi ke Jenkins production. Skenario utama saat ini menggunakan Jenkins server pada `10.216.83.114:8088`, sedangkan Jenkins lokal tetap dapat dipakai sebagai fallback pengembangan. Dokumen ini juga menjawab kebutuhan paling praktis dari tim pengembang: bagaimana mendapatkan token integrasi, apa yang harus diisi di Jenkins, apa yang harus ditambahkan di YAML, dan bagaimana membaca hasil gate dari SATRIA.

## Tujuan skenario

Skenario ini dipakai untuk memvalidasi bahwa pipeline:

- mampu mendaftarkan release ke SATRIA
- mampu membuat scan job berbasis image
- mampu membaca hasil dan keputusan gate
- mampu berhenti otomatis bila release tidak lolos
- mampu meneruskan temuan berat ke IRIS bila dibutuhkan
- mampu dipahami dan direplikasi oleh tim pengembang tanpa harus menebak kontrak integrasi

## Topologi uji

- Jenkins server berjalan pada host `10.216.83.114`
- Jenkins memanggil SATRIA remote melalui HTTP API
- SATRIA menjalankan scan melalui worker yang terhubung ke Trivy, Syft, Grype, ZAP, dan integrasi IRIS

Topologi operasional untuk pengujian saat ini:

- Jenkins UI: `http://10.216.83.114:8088`
- SATRIA: `http://10.216.208.249:8090`
- Job contoh: `satria-security-gate`
- Job demo lolos: `satria-gate-passed-demo`
- Job demo gagal: `satria-gate-failed-demo`

Topologi lokal masih tersedia untuk pengembangan:

- Jenkins lokal: `http://localhost:8088`
- SATRIA lokal: `http://localhost:8090`

## Cara mendapatkan API key atau token SATRIA

Pada implementasi SATRIA saat ini, token pipeline belum dibuat melalui menu UI. Mekanismenya masih melalui administrator SATRIA.

### Langkah yang harus dilakukan tim pengembang

1. Ajukan permintaan service account integrasi ke administrator SATRIA.
2. Sertakan informasi minimal:
   - nama aplikasi
   - kode aset
   - nama pipeline atau nama project Jenkins/GitLab
   - kebutuhan scope
   - environment target yang akan memakai integrasi
3. Minta minimal hak berikut:
   - `release:write`
   - `scan:create`
   - `scan:read`
4. Tambahkan `ticket:publish` hanya bila pipeline memang boleh membuat tiket ke IRIS.
5. Setelah token diberikan, simpan token itu di credential manager CI/CD, bukan di repository.

### Contoh konfigurasi di backend SATRIA

Administrator SATRIA menyiapkan token melalui environment backend, misalnya:

```env
SATRIA_API_SERVICE_ACCOUNT=pipeline-service
SATRIA_API_TOKEN=replace-with-long-random-token
SATRIA_API_SCOPES=release:write,scan:create,scan:read,ticket:publish
```

Token ini lalu dipakai pipeline sebagai:

```http
Authorization: Bearer <SATRIA_TOKEN>
```

## Konfigurasi Jenkins yang harus disiapkan

### 1. Buat credential di Jenkins

Pada Jenkins UI:

1. `Manage Jenkins`
2. `Credentials`
3. `System`
4. `Global credentials (unrestricted)`
5. `Add Credentials`
6. Pilih `Kind = Secret text`
7. Isi:
   - `Secret`: token SATRIA dari administrator
   - `ID`: `satria-api-token`
   - `Description`: `Bearer token integrasi SATRIA`

### 2. Variabel minimum yang dipakai pipeline

- `SATRIA_URL`
- `SATRIA_TOKEN`
- `SATRIA_ASSET_CODE`
- `SATRIA_ASSET_NAME`
- `IMAGE_REF`
- `SCAN_PROFILE`
- `ENVIRONMENT_TARGET`

### 3. Contoh environment di Jenkinsfile

```groovy
environment {
  SATRIA_URL = "http://10.216.208.249:8090"
  SATRIA_TOKEN = credentials("satria-api-token")
  SATRIA_ASSET_CODE = "SAKTI-API"
  SATRIA_ASSET_NAME = "SAKTI API"
  REGISTRY_IMAGE = "registry.internal/sakti-api:${BUILD_NUMBER}-${GIT_COMMIT.take(8)}"
}
```

## Apa yang harus ditambahkan di YAML CI/CD

### A. Contoh `.gitlab-ci.yml`

Tambahkan stage security gate setelah build dan push:

```yaml
stages:
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
```

### B. Contoh variabel di `.env` Jenkins lokal

```env
JENKINS_HTTP_PORT=8088
JENKINS_AGENT_PORT=50088
JENKINS_ADMIN_ID=admin
JENKINS_ADMIN_PASSWORD=admin123!
SATRIA_URL=http://host.docker.internal:8090
SATRIA_API_TOKEN=change-me-pipeline-token
SATRIA_ASSET_CODE=JENKINS-DEMO
SATRIA_ASSET_NAME=Jenkins Demo Service
```

## Payload minimum yang dikirim pipeline

### Intake release

```json
{
  "asset_code": "SAKTI-API",
  "asset_name": "SAKTI API",
  "release_version": "release-2026.07.04-201-a1b2c3d4",
  "image_ref": "registry.internal/sakti-api:release-2026.07.04-201-a1b2c3d4",
  "image_digest": "registry.internal/sakti-api@sha256:abc123...",
  "git_commit": "a1b2c3d4",
  "build_number": "201",
  "environment_target": "production"
}
```

### Create scan

```json
{
  "asset_id": 12,
  "release_id": 8,
  "image_ref": "registry.internal/sakti-api:release-2026.07.04-201-a1b2c3d4",
  "scan_profile": "quick_container",
  "requested_by": "jenkins",
  "build_number": "201"
}
```

## Alur uji yang disarankan

1. Developer membuka Jenkins server di `http://10.216.83.114:8088`
2. Login menggunakan akun admin lokal yang diset pada file `.env`
3. Buka job `satria-security-gate`
4. Jalankan build dengan parameter:
   - `IMAGE_REF=nginx:latest`
   - `ASSET_CODE=JENKINS-DEMO`
   - `ASSET_NAME=Jenkins Demo Service`
   - `SCAN_PROFILE=quick_container`
   - `ENVIRONMENT_TARGET=staging`
   - `PUBLISH_TO_IRIS=false`
5. Jenkins membuat intake release ke SATRIA
6. SATRIA mengembalikan `asset_id` dan `release_id`
7. Jenkins membuat scan job
8. Jenkins polling hasil sampai status final
9. Jenkins mengambil `scan-result.json`
10. Jenkins mengevaluasi `decision`

## Urutan endpoint yang benar

1. `POST /api/v1/releases/intake`
2. `POST /api/v1/scans`
3. `GET /api/v1/scans/{scan_id}`
4. `GET /api/v1/scans/{scan_id}/result`
5. `POST /api/v1/scans/{scan_id}/publish-ticket` bila diperlukan

## Interpretasi hasil

- `allowed`: release boleh lanjut ke stage berikutnya
- `need_approval`: release perlu persetujuan manual
- `blocked`: release harus berhenti

Jika hasil `blocked`, itu bukan berarti integrasi gagal. Justru itu berarti SATRIA berhasil menjadi security gate.

## Variasi pengujian

### Uji tanpa ticket IRIS

- `PUBLISH_TO_IRIS=false`
- fokus pada alur intake, scan, polling, dan gate

### Uji dengan ticket IRIS

- `PUBLISH_TO_IRIS=true`
- Jenkins akan memanggil endpoint publish ticket SATRIA
- SATRIA meneruskan temuan `critical/high` ke IRIS

## Artefak yang sebaiknya disimpan pipeline

- `release-intake.json`
- `release-response.json`
- `scan-request.json`
- `scan-response.json`
- `scan-status.json`
- `scan-result.json`
- `publish-response.json` bila publish diaktifkan

## Hasil smoke test yang sudah terbukti

Build Jenkins server terbaru berhasil membuktikan:

- intake release berhasil
- create scan job berhasil
- polling status berhasil
- hasil scan JSON berhasil dibaca
- gate decision berhasil memblokir release

Contoh hasil riil:

- `scan_id=18`
- `status=completed`
- `mode=real`
- `decision=blocked`
- total finding `372`
- severity:
  - critical `2`
  - high `39`
  - medium `118`
  - low `142`
  - informational `71`

## Catatan operasional

- Untuk uji awal, gunakan image publik agar worker SATRIA dapat langsung menarik image.
- Untuk uji internal, gunakan image yang memang dapat diakses dari server SATRIA.
- SATRIA saat ini belum menyediakan self-service API key dari UI, sehingga koordinasi dengan administrator masih wajib untuk tahap awal integrasi.
- Bila ingin publish ke IRIS secara otomatis, aktifkan hanya untuk severity yang memang perlu remediation formal agar case tidak berlebihan.
