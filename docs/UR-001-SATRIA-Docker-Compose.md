# UR-001 — Pengembangan Platform SATRIA Berbasis Docker Compose

**Nama Platform:** SATRIA  
**Kepanjangan:** Security Assessment, Tracking, Remediation, and Incident Automation  
**Versi Dokumen:** 1.0  
**Tanggal:** 29 Juni 2026  
**Jenis Dokumen:** User Requirement dan Technical Requirement Awal  
**Model Deployment:** Satu Docker Compose environment berisi SATRIA, scanner engine, DFIR-IRIS, dan database.

---

## 1. Ringkasan Eksekutif

Dibutuhkan pengembangan **Platform SATRIA** sebagai platform internal terpadu untuk mendukung proses **security assessment, vulnerability management, remediation tracking, dan incident/case management**.

Platform SATRIA dikembangkan sebagai **1 Docker Compose environment** yang terdiri atas beberapa service/container terpisah. Dari sisi pengguna, SATRIA tampil sebagai satu aplikasi terpadu. Dari sisi teknis, setiap komponen berjalan secara modular agar mudah dikelola, diperbarui, dipantau, dan dikembangkan.

Platform ini akan mengintegrasikan beberapa tool open source berikut:

| Komponen | Fungsi Utama dalam SATRIA |
|---|---|
| **Trivy** | Scanner vulnerability, misconfiguration, secret, SBOM untuk container, repository, filesystem, Kubernetes, dan cloud-native asset. |
| **Syft** | Generate Software Bill of Materials / SBOM dari container image dan filesystem. |
| **Grype** | Vulnerability scanner untuk container image, filesystem, dan SBOM. |
| **OpenVAS / Greenbone** | Vulnerability assessment untuk IP, server, port, service, dan network asset. |
| **OWASP ZAP** | Dynamic Application Security Testing / DAST untuk web application dan API. |
| **DFIR-IRIS** | Collaborative incident response, case/ticket management, evidence, task, IOC, timeline, dan remediation tracking. |
| **SATRIA Backend & Dashboard** | Orchestrator, database temuan, normalisasi hasil scan, risk scoring, dashboard, report, dan integrasi ke DFIR-IRIS. |

---

## 2. Latar Belakang

Proses pengujian keamanan aplikasi dan infrastruktur umumnya menggunakan beberapa tool yang berjalan secara terpisah. Masing-masing tool memiliki target dan format output yang berbeda.

Permasalahan yang ingin diselesaikan:

| Permasalahan | Dampak |
|---|---|
| Scanner berjalan sendiri-sendiri | Hasil scan tersebar dan sulit dikonsolidasikan. |
| Format output berbeda-beda | Perlu proses manual untuk membaca dan membandingkan hasil. |
| Temuan vulnerability dapat muncul berulang dari beberapa scanner | Menimbulkan duplikasi dan kesulitan menentukan prioritas. |
| Tidak ada histori scan terpusat | Sulit membandingkan hasil sebelum dan sesudah remediation. |
| Tidak ada integrasi langsung dengan ticket/case management | Temuan tidak otomatis menjadi action item. |
| Laporan teknis dan manajerial disusun manual | Membutuhkan waktu dan rawan inkonsistensi. |
| Active scanner seperti OpenVAS dan ZAP belum dikendalikan secara terpusat | Berisiko apabila dijalankan terhadap target yang tidak tepat. |

Dengan Platform SATRIA, proses yang diharapkan menjadi:

```text
Asset Inventory
   → Scan Orchestration
   → Raw Report Collection
   → Finding Normalization
   → Deduplication
   → Risk Scoring
   → Dashboard & Reporting
   → DFIR-IRIS Case/Ticket
   → Remediation
   → Retest
   → Closure
```

---

## 3. Tujuan Pengembangan

Tujuan pengembangan Platform SATRIA adalah:

1. Menyediakan satu platform internal untuk mengelola proses security assessment lintas target.
2. Mengorkestrasi scanner open source sesuai jenis asset dan kebutuhan scan.
3. Menghasilkan database temuan keamanan yang terpusat dan terstruktur.
4. Melakukan normalisasi hasil scan dari Trivy, Syft, Grype, OpenVAS, dan OWASP ZAP.
5. Mengurangi duplikasi temuan dengan mekanisme deduplication.
6. Memberikan risk scoring berbasis severity, CVSS, asset criticality, exposure, dan exploitability.
7. Mengintegrasikan temuan prioritas ke DFIR-IRIS sebagai alert, case, task, dan evidence.
8. Mendukung proses remediation, retest, closure, audit trail, dan pelaporan.
9. Menjadi platform pendukung Secure SDLC, vulnerability assessment, pentest internal, dan incident response.

---

## 4. Pernyataan User Requirement

**UR-001:**  
Dibutuhkan pengembangan **Platform SATRIA** sebagai platform security assessment dan remediation tracking terpadu berbasis **Docker Compose environment** yang mengintegrasikan SATRIA Dashboard, backend orchestrator, database, job queue, storage, scanner workers, OpenVAS/Greenbone, OWASP ZAP, serta DFIR-IRIS. Platform harus mampu menerima target berupa container image, source repository, filesystem, IP/server, web application, dan API; menjalankan scanner yang sesuai; menyimpan raw report; menormalisasi dan mendeduplikasi temuan; menghitung risk score; menampilkan dashboard; menghasilkan laporan; serta mengirim temuan prioritas ke DFIR-IRIS untuk proses case/ticket management, remediation, retest, dan closure.

---

## 5. Model Deployment yang Dipilih

### 5.1 Prinsip Deployment

Platform SATRIA dikembangkan sebagai:

> **Satu Docker Compose project yang berisi banyak service/container modular.**

Bukan sebagai satu container tunggal yang berisi seluruh aplikasi dan scanner.

### 5.2 Alasan Tidak Menggunakan Satu Container Tunggal

| Alasan | Penjelasan |
|---|---|
| Kompleksitas dependency | Trivy, Syft, Grype, ZAP, OpenVAS, DFIR-IRIS, PostgreSQL, Redis/RabbitMQ memiliki dependency berbeda. |
| Maintenance sulit | Update satu tool dapat mengganggu tool lain. |
| Troubleshooting sulit | Error scanner, database, dan aplikasi bercampur dalam satu runtime. |
| Scaling tidak fleksibel | Worker scan tidak bisa diperbanyak secara independen. |
| Security risk lebih besar | Semua komponen berbagi satu boundary container. |
| OpenVAS dan DFIR-IRIS memang stack multi-service | Keduanya lebih tepat berjalan sebagai service/stack terpisah. |

### 5.3 Model yang Disepakati

| Komponen | Model Container |
|---|---|
| SATRIA Frontend | Container tersendiri. |
| SATRIA Backend API | Container tersendiri. |
| PostgreSQL SATRIA | Container database tersendiri. |
| Redis/RabbitMQ | Container queue tersendiri. |
| MinIO / shared storage | Container storage tersendiri atau volume lokal. |
| Trivy + Syft + Grype | Dapat digabung dalam satu scanner worker container untuk MVP. |
| OWASP ZAP | Container/worker tersendiri. |
| OpenVAS/Greenbone | Stack/service tersendiri dalam Docker Compose. |
| DFIR-IRIS | Stack/service tersendiri dalam Docker Compose. |

---

## 6. Referensi Source Open Source

| No | Komponen | Source | Keterangan Implementasi |
|---:|---|---|---|
| 1 | Syft-Grype | https://github.com/Syft-Grype | Link yang diberikan sebagai referensi awal. Untuk implementasi teknis, gunakan repo resmi Anchore Syft dan Anchore Grype. |
| 2 | Syft | https://github.com/anchore/syft | Digunakan untuk menghasilkan SBOM dari container image dan filesystem. |
| 3 | Grype | https://github.com/anchore/grype | Digunakan untuk vulnerability scanning terhadap image, filesystem, dan SBOM. |
| 4 | OpenVAS Scanner | https://github.com/greenbone/openvas-scanner | Digunakan sebagai scan engine untuk IP/server/network vulnerability assessment. |
| 5 | Greenbone Community Containers | https://greenbone.github.io/docs/latest/22.4/container/index.html | Referensi deployment OpenVAS/Greenbone berbasis container. |
| 6 | Trivy | https://github.com/aquasecurity/trivy | Digunakan untuk scan vulnerability, misconfiguration, secret, SBOM, container, repository, filesystem, Kubernetes, dan cloud-native asset. |
| 7 | OWASP ZAP | https://github.com/zaproxy/zaproxy | Digunakan untuk DAST web application dan API. |
| 8 | DFIR-IRIS | https://github.com/dfir-iris/iris-web | Digunakan sebagai collaborative incident response dan case/ticket management. |
| 9 | DFIR-IRIS Docs | https://docs.dfir-iris.org/latest/getting_started/ | Referensi deployment DFIR-IRIS menggunakan Docker Compose. |
| 10 | Docker Compose Services | https://docs.docker.com/reference/compose-file/services/ | Referensi konsep services pada Docker Compose. |

---

## 7. Ruang Lingkup

### 7.1 In Scope

| Area | Keterangan |
|---|---|
| Asset inventory | Mencatat aplikasi, server, IP, URL, API, repository, container image, owner, environment, dan criticality. |
| Scan orchestration | Menentukan scanner yang sesuai berdasarkan jenis target dan scan profile. |
| Container scanning | Menggunakan Trivy, Syft, dan Grype. |
| Repository scanning | Menggunakan Trivy dan Syft. |
| Filesystem scanning | Menggunakan Trivy, Syft, dan Grype. |
| SBOM generation | Menggunakan Syft dan/atau Trivy. |
| SBOM vulnerability scan | Menggunakan Grype dan/atau Trivy. |
| Infrastructure scanning | Menggunakan OpenVAS/Greenbone. |
| Web/API scanning | Menggunakan OWASP ZAP. |
| Raw report storage | Menyimpan output JSON, XML, HTML, SBOM, dan log scanner. |
| Finding normalization | Menyamakan format hasil scan dari berbagai scanner. |
| Deduplication | Menggabungkan temuan yang sama agar tidak tercatat berulang. |
| Risk scoring | Menghitung prioritas berdasarkan severity, CVSS, criticality, exposure, dan exploitability. |
| Remediation tracking | Mengelola status temuan dari open sampai closed. |
| DFIR-IRIS integration | Mengirim finding sebagai alert, case, task, evidence, IOC, dan timeline. |
| Dashboard | Menampilkan rekap severity, status remediation, SLA, asset risk, dan tren temuan. |
| Reporting | Menghasilkan laporan teknis, executive summary, dan remediation report. |
| Audit log | Mencatat aktivitas user, scanner, status change, assignment, dan closure. |

### 7.2 Out of Scope Tahap Awal

| Area | Keterangan |
|---|---|
| Auto exploit | Platform tidak melakukan eksploitasi otomatis. |
| Auto remediation | Platform tidak melakukan patching atau perubahan konfigurasi otomatis pada tahap awal. |
| Full SAST engine | Tidak menggantikan SonarQube, Semgrep, CodeQL, atau SAST khusus. |
| Full SOAR | Belum menjadi platform SOAR otomatis penuh. |
| Production active scan tanpa approval | Active scan terhadap production wajib melalui whitelist dan approval. |
| Credentialed scan masif | Authenticated scan dapat menjadi pengembangan lanjutan. |

---

## 8. Jenis Target dan Scanner yang Digunakan

| Jenis Target | Contoh | Scanner Utama | Scanner Tambahan |
|---|---|---|---|
| Container image | `registry.local/sakti-api:latest` | Trivy | Syft, Grype |
| Source repository | Git repository aplikasi | Trivy | Syft |
| Filesystem / folder build | `/scan/source/app` | Trivy | Syft, Grype |
| SBOM | CycloneDX/SPDX/Syft JSON | Grype | Trivy |
| IP/server | `10.100.244.90` | OpenVAS | - |
| Network range | `10.100.244.0/24` | OpenVAS | - |
| Web application | `https://app-dev.local` | OWASP ZAP | OpenVAS untuk host/IP bila diperlukan |
| API endpoint | OpenAPI/Swagger URL | OWASP ZAP | Trivy repo/config bila ada source repo |
| Kubernetes/cluster config | K8s manifest/cluster | Trivy | Pengembangan lanjutan |

---

## 9. Arsitektur Logis

```text
[User / Security Analyst / Pentester / DevSecOps]
                  |
                  v
        [SATRIA Web Dashboard]
                  |
                  v
        [SATRIA Backend API]
                  |
                  v
        [Scan Orchestrator]
                  |
   +--------------+---------------+----------------+----------------+
   |                              |                |                |
   v                              v                v                v
[Worker Trivy/Syft/Grype]   [Worker ZAP]   [Greenbone/OpenVAS]   [DFIR-IRIS Connector]
   |                              |                |                |
   +--------------+---------------+----------------+----------------+
                  |
                  v
        [Finding Normalizer]
                  |
                  v
        [SATRIA PostgreSQL Database]
                  |
                  v
        [Dashboard / Report / Remediation]
                  |
                  v
        [DFIR-IRIS Alert / Case / Task / Evidence]
```

---

## 10. Arsitektur Docker Compose Environment

### 10.1 Komponen Utama

| Service | Fungsi | Keterangan |
|---|---|---|
| `satria-frontend` | UI/dashboard | Menyediakan antarmuka pengguna. |
| `satria-backend` | API dan orchestrator | Mengelola asset, scan job, finding, report, user, integrasi scanner. |
| `satria-db` | PostgreSQL | Menyimpan asset, scan job, finding, user, audit log, mapping IRIS. |
| `satria-redis` atau `satria-rabbitmq` | Queue | Mengelola antrean scan job. |
| `satria-minio` | Object storage | Menyimpan raw report, SBOM, JSON, XML, HTML, PDF. |
| `worker-trivy-syft-grype` | Scanner worker | Menjalankan Trivy, Syft, dan Grype. |
| `worker-zap` | Web/API scanner worker | Menjalankan ZAP baseline/full/API scan. |
| `greenbone-*` | OpenVAS/Greenbone stack | Menjalankan scan IP/server/network. |
| `iris-web` | DFIR-IRIS web app | Case/ticket management. |
| `iris-db` | Database DFIR-IRIS | Database IRIS. |
| `iris-worker` | Worker DFIR-IRIS | Worker internal IRIS. |
| `iris-rabbitmq` | Queue DFIR-IRIS | Queue internal IRIS. |
| `nginx` atau reverse proxy | Routing | Reverse proxy untuk SATRIA, IRIS, dan Greenbone bila diperlukan. |

### 10.2 Network Segment dalam Docker Compose

| Network | Komponen | Fungsi |
|---|---|---|
| `frontend-net` | frontend, reverse proxy | Akses UI pengguna. |
| `backend-net` | backend, database, queue, storage | Komunikasi aplikasi internal. |
| `scanner-net` | backend, scanner worker, ZAP, OpenVAS | Komunikasi orchestrator dengan scanner. |
| `case-net` | backend, DFIR-IRIS | Integrasi case/ticket. |
| `restricted-scan-net` | scanner worker | Network khusus untuk mengontrol akses scanner ke target internal. |

### 10.3 Volume Persisten

| Volume | Digunakan Oleh | Isi |
|---|---|---|
| `satria_db_data` | PostgreSQL SATRIA | Database SATRIA. |
| `satria_minio_data` | MinIO | Raw report dan evidence. |
| `satria_scan_workspace` | Scanner workers | Temporary workspace scan. |
| `trivy_cache` | Worker Trivy | Cache vulnerability DB. |
| `grype_cache` | Worker Grype | Cache vulnerability DB. |
| `greenbone_data` | Greenbone/OpenVAS | Feed, config, report, data scanner. |
| `iris_db_data` | DFIR-IRIS DB | Database IRIS. |
| `iris_uploads` | DFIR-IRIS | Evidence/upload IRIS. |

---

## 11. Contoh Struktur Folder Repository

```text
satria-platform/
├── README.md
├── docker-compose.yml
├── .env.example
├── docs/
│   ├── architecture.md
│   ├── api.md
│   ├── scanner-integration.md
│   └── deployment.md
├── frontend/
│   └── Dockerfile
├── backend/
│   ├── Dockerfile
│   ├── app/
│   └── migrations/
├── workers/
│   ├── trivy-syft-grype/
│   │   ├── Dockerfile
│   │   ├── run_trivy.py
│   │   ├── run_syft.py
│   │   └── run_grype.py
│   └── zap/
│       ├── Dockerfile
│       └── run_zap.py
├── parsers/
│   ├── trivy_parser.py
│   ├── syft_parser.py
│   ├── grype_parser.py
│   ├── openvas_parser.py
│   └── zap_parser.py
├── integrations/
│   ├── dfir_iris_client.py
│   └── greenbone_client.py
├── reports/
│   ├── templates/
│   └── generated/
└── storage/
    ├── raw/
    ├── sbom/
    └── evidence/
```

---

## 12. Contoh Konseptual Docker Compose

> Catatan: file di bawah adalah contoh konseptual untuk kebutuhan desain. Tim pengembang perlu menyesuaikan image, secret, network, volume, dan konfigurasi sesuai environment internal.

```yaml
services:
  satria-frontend:
    image: satria/frontend:latest
    container_name: satria-frontend
    ports:
      - "8080:80"
    depends_on:
      - satria-backend
    networks:
      - frontend-net
      - backend-net

  satria-backend:
    image: satria/backend:latest
    container_name: satria-backend
    environment:
      DATABASE_URL: postgresql://satria:${SATRIA_DB_PASSWORD}@satria-db:5432/satria
      REDIS_URL: redis://satria-redis:6379/0
      MINIO_ENDPOINT: http://satria-minio:9000
      IRIS_URL: https://iris-web
      GREENBONE_URL: https://greenbone-gsad
    depends_on:
      - satria-db
      - satria-redis
      - satria-minio
    networks:
      - backend-net
      - scanner-net
      - case-net

  satria-db:
    image: postgres:16
    container_name: satria-db
    environment:
      POSTGRES_DB: satria
      POSTGRES_USER: satria
      POSTGRES_PASSWORD: ${SATRIA_DB_PASSWORD}
    volumes:
      - satria_db_data:/var/lib/postgresql/data
    networks:
      - backend-net

  satria-redis:
    image: redis:7
    container_name: satria-redis
    networks:
      - backend-net

  satria-minio:
    image: minio/minio:latest
    container_name: satria-minio
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: ${MINIO_ROOT_USER}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
    volumes:
      - satria_minio_data:/data
    networks:
      - backend-net

  worker-trivy-syft-grype:
    image: satria/worker-trivy-syft-grype:latest
    container_name: worker-trivy-syft-grype
    environment:
      BACKEND_URL: http://satria-backend:8000
      REDIS_URL: redis://satria-redis:6379/0
    volumes:
      - satria_scan_workspace:/workspace
      - trivy_cache:/root/.cache/trivy
      - grype_cache:/root/.cache/grype
      # Optional, only if image scanning requires Docker socket access.
      # Use carefully and restrict permissions.
      # - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on:
      - satria-backend
      - satria-redis
    networks:
      - backend-net
      - scanner-net

  worker-zap:
    image: ghcr.io/zaproxy/zaproxy:stable
    container_name: worker-zap
    volumes:
      - satria_scan_workspace:/zap/wrk
    networks:
      - scanner-net

  # Greenbone/OpenVAS stack should follow official Greenbone Community Container pattern.
  # It may be included in the same Compose project or maintained as an adjacent Compose file.
  # SATRIA Backend integrates with it through API/GMP.

  # DFIR-IRIS stack should follow official DFIR-IRIS Docker Compose pattern.
  # SATRIA Backend integrates with IRIS through API.

networks:
  frontend-net:
  backend-net:
  scanner-net:
  case-net:

volumes:
  satria_db_data:
  satria_minio_data:
  satria_scan_workspace:
  trivy_cache:
  grype_cache:
```

---

## 13. Modul Fungsional SATRIA

### 13.1 Asset Inventory

Modul untuk mencatat target keamanan.

| Field | Keterangan |
|---|---|
| Asset ID | ID unik asset. |
| Nama Asset | Nama aplikasi/server/repo/image/API. |
| Jenis Asset | Application, API, server, container image, repository, filesystem, Kubernetes. |
| Environment | Development, staging, production. |
| Owner Unit | Unit pemilik aplikasi/asset. |
| Technical PIC | PIC developer/sysadmin. |
| Business Criticality | Critical, high, medium, low. |
| URL | URL aplikasi/API. |
| IP Address | IP server. |
| Repository URL | URL Git repository. |
| Container Image | Nama image dan tag. |
| Scan Profile Default | Quick, standard, full, compliance. |
| Whitelist Active Scan | Ya/tidak. |
| Status Asset | Active, inactive, decommissioned. |

### 13.2 Scan Profile

| Scan Profile | Scanner | Keterangan |
|---|---|---|
| Quick Container Scan | Trivy | Scan cepat vulnerability image. |
| Full Container Scan | Trivy + Syft + Grype | Scan lengkap image, SBOM, dan vulnerability. |
| SBOM Generation | Syft | Membuat SBOM CycloneDX/SPDX/Syft JSON. |
| SBOM Vulnerability Scan | Grype | Scan CVE berdasarkan SBOM. |
| Repo Security Scan | Trivy + Syft | Scan repository, dependency, secret, dan konfigurasi. |
| Filesystem Scan | Trivy + Syft + Grype | Scan folder hasil build/source. |
| Infra VA Scan | OpenVAS | Scan IP/server/port/service. |
| Web Baseline Scan | OWASP ZAP | Passive/baseline scan. |
| Web Full Scan | OWASP ZAP | Active scan, hanya untuk target yang diizinkan. |
| API Scan | OWASP ZAP | Scan API berdasarkan OpenAPI/Swagger bila tersedia. |
| Retest Scan | Scanner sesuai finding | Validasi hasil remediation. |

### 13.3 Scanner Orchestrator

Fungsi:

1. Menerima permintaan scan dari user atau scheduler.
2. Memvalidasi jenis target dan whitelist active scan.
3. Menentukan scanner yang harus dijalankan.
4. Membuat scan job dan memasukkannya ke queue.
5. Mengirim job ke worker yang sesuai.
6. Memantau status job: `queued`, `running`, `completed`, `failed`, `cancelled`.
7. Mengambil raw report.
8. Memanggil parser dan finding normalizer.
9. Mengirim finding prioritas ke DFIR-IRIS.
10. Menyediakan hasil scan ke dashboard dan laporan.

### 13.4 Scanner Worker

| Worker | Input | Output |
|---|---|---|
| Trivy Worker | image, repo, filesystem, config | JSON vulnerability/misconfiguration/secret/SBOM. |
| Syft Worker | image, filesystem | SBOM CycloneDX/SPDX/Syft JSON. |
| Grype Worker | image, filesystem, SBOM | JSON vulnerability report. |
| ZAP Worker | URL/API/context file | JSON/HTML DAST report. |
| OpenVAS Connector | IP/server/network range | XML/JSON/HTML vulnerability report. |
| IRIS Connector | normalized finding | alert/case/task/evidence di DFIR-IRIS. |

---

## 14. Detail Integrasi Scanner

### 14.1 Trivy

Fungsi dalam SATRIA:

| Kapabilitas | Keterangan |
|---|---|
| Image scan | Mendeteksi CVE pada container image. |
| Filesystem scan | Mendeteksi dependency dan vulnerability dari folder. |
| Repo scan | Mendeteksi vulnerability, secret, license, dan misconfiguration pada repository. |
| IaC scan | Mendeteksi misconfiguration pada file konfigurasi/IaC. |
| Secret scan | Mendeteksi credential/token yang tertanam. |
| Kubernetes scan | Pengembangan lanjutan untuk cluster atau manifest. |
| SBOM output | Mendukung output SBOM untuk kebutuhan supply chain. |

Contoh perintah:

```bash
trivy image --format json --output /reports/trivy-image.json registry.local/app:latest
trivy fs --format json --output /reports/trivy-fs.json /workspace/source
trivy repo --format json --output /reports/trivy-repo.json https://github.local/group/app
trivy config --format json --output /reports/trivy-config.json /workspace/iac
```

### 14.2 Syft

Fungsi dalam SATRIA:

| Kapabilitas | Keterangan |
|---|---|
| Generate SBOM image | Membuat daftar komponen software dalam image. |
| Generate SBOM filesystem | Membuat daftar komponen software dari folder. |
| Output standar | CycloneDX, SPDX, Syft JSON. |
| Evidence supply chain | Menjadi bukti komponen software untuk audit/compliance. |

Contoh perintah:

```bash
syft registry.local/app:latest -o cyclonedx-json > /reports/sbom-cyclonedx.json
syft registry.local/app:latest -o spdx-json > /reports/sbom-spdx.json
syft dir:/workspace/source -o syft-json > /reports/sbom-syft.json
```

### 14.3 Grype

Fungsi dalam SATRIA:

| Kapabilitas | Keterangan |
|---|---|
| Image vulnerability scan | Scan CVE pada container image. |
| Filesystem vulnerability scan | Scan CVE pada dependency/folder aplikasi. |
| SBOM vulnerability scan | Scan CVE berdasarkan SBOM dari Syft. |
| Validation scanner | Dapat digunakan sebagai pembanding hasil Trivy untuk package/SBOM. |

Contoh perintah:

```bash
grype registry.local/app:latest -o json > /reports/grype-image.json
grype dir:/workspace/source -o json > /reports/grype-fs.json
grype sbom:/reports/sbom-cyclonedx.json -o json > /reports/grype-sbom.json
```

### 14.4 OpenVAS / Greenbone

Fungsi dalam SATRIA:

| Kapabilitas | Keterangan |
|---|---|
| Host vulnerability scan | Scan IP/server. |
| Service vulnerability scan | Scan service berdasarkan port. |
| Network vulnerability assessment | Scan subnet/range IP. |
| Feed-based VT scan | Menggunakan Vulnerability Tests. |
| Credentialed scan | Pengembangan lanjutan dengan izin dan credential aman. |

Integrasi disarankan:

1. OpenVAS/Greenbone dijalankan sebagai stack tersendiri dalam Docker Compose.
2. SATRIA membuat target scan ke Greenbone melalui API/GMP.
3. SATRIA memantau status scan.
4. SATRIA mengambil report XML/HTML/JSON.
5. Parser SATRIA mengubah report menjadi finding internal.

### 14.5 OWASP ZAP

Fungsi dalam SATRIA:

| Kapabilitas | Keterangan |
|---|---|
| Baseline scan | Passive/baseline scan untuk web app. |
| Full scan | Active scan terhadap web app yang diizinkan. |
| API scan | Scan API berdasarkan OpenAPI/Swagger. |
| Header check | HSTS, CSP, X-Frame-Options, cookie flags. |
| Web vulnerability | XSS, injection, weak config, exposed information. |

Contoh perintah:

```bash
zap-baseline.py -t https://app-dev.local -J /zap/wrk/zap-baseline.json -r /zap/wrk/zap-baseline.html
zap-full-scan.py -t https://app-dev.local -J /zap/wrk/zap-full.json -r /zap/wrk/zap-full.html
zap-api-scan.py -t https://app-dev.local/openapi.json -f openapi -J /zap/wrk/zap-api.json -r /zap/wrk/zap-api.html
```

Kendali keamanan:

| Kontrol | Keterangan |
|---|---|
| Default mode | Baseline/passive scan. |
| Active scan | Hanya jika asset memiliki whitelist active scan. |
| Production scan | Harus melalui approval dan jadwal yang disepakati. |
| Rate limit | Perlu opsi pembatasan request. |
| Authenticated context | Dapat menjadi tahap lanjutan. |

### 14.6 DFIR-IRIS

Fungsi dalam SATRIA:

| Fungsi | Keterangan |
|---|---|
| Alert intake | Menerima finding prioritas dari SATRIA. |
| Case management | Mengelola case per asset atau per incident. |
| Task remediation | Membuat tugas perbaikan kepada PIC. |
| Evidence | Menyimpan raw report, screenshot, JSON, XML, HTML, SBOM. |
| IOC | Menyimpan IP/domain/hash bila relevan. |
| Timeline | Mencatat kronologi penanganan. |
| Closure | Menutup case setelah remediation dan retest. |

Mapping SATRIA ke DFIR-IRIS:

| SATRIA | DFIR-IRIS |
|---|---|
| Critical/high finding | Alert |
| Kumpulan finding pada asset penting | Case |
| Asset terdampak | Asset |
| Rekomendasi perbaikan | Task |
| Raw report | Evidence |
| IP/domain/hash | IOC |
| Hasil retest | Evidence tambahan |
| Status closure | Case/task closure |

---

## 15. Normalisasi Data Temuan

### 15.1 Skema Finding Internal

```json
{
  "finding_id": "SATRIA-FND-000001",
  "scan_id": "SATRIA-SCAN-20260629-0001",
  "asset_id": "APP-SAKTI-001",
  "asset_name": "SAKTI API",
  "asset_type": "container_image",
  "environment": "development",
  "scanner": "trivy",
  "scanner_version": "auto-detected",
  "finding_type": "container_vulnerability",
  "title": "CVE-XXXX-YYYY in openssl",
  "description": "Detected vulnerable package openssl",
  "severity_original": "CRITICAL",
  "severity_normalized": "Critical",
  "cve": "CVE-XXXX-YYYY",
  "cwe": null,
  "cvss_score": 9.8,
  "package_name": "openssl",
  "installed_version": "x.x.x",
  "fixed_version": "y.y.y",
  "affected_component": "container layer / OS package",
  "ip": null,
  "port": null,
  "protocol": null,
  "url": null,
  "parameter": null,
  "evidence": "path/package/service/URL/parameter",
  "recommendation": "Upgrade package to fixed version",
  "references": [
    "vendor advisory",
    "scanner reference"
  ],
  "risk_score": 95,
  "status": "Open",
  "assigned_to": "developer/sysadmin/security",
  "first_detected_at": "2026-06-29T10:00:00+07:00",
  "last_seen_at": "2026-06-29T10:00:00+07:00",
  "resolved_at": null,
  "iris_alert_id": null,
  "iris_case_id": null
}
```

### 15.2 Kategori Finding

| Kategori | Sumber Scanner |
|---|---|
| `container_vulnerability` | Trivy, Grype |
| `dependency_vulnerability` | Trivy, Grype |
| `sbom_component` | Syft |
| `secret_exposure` | Trivy |
| `iac_misconfiguration` | Trivy |
| `host_vulnerability` | OpenVAS |
| `network_service_vulnerability` | OpenVAS |
| `web_vulnerability` | OWASP ZAP |
| `api_vulnerability` | OWASP ZAP |
| `security_header_issue` | OWASP ZAP |
| `informational_finding` | Semua scanner |

---

## 16. Deduplikasi Temuan

### 16.1 Kunci Deduplikasi

| Jenis Temuan | Kunci Deduplikasi |
|---|---|
| CVE package | `asset_id + cve + package_name + installed_version` |
| CVE image | `image_digest + cve + package_name` |
| SBOM component | `asset_id + package_name + version + purl` |
| Web finding | `asset_id + url + parameter + cwe + finding_title` |
| Security header | `asset_id + url + header_name + finding_type` |
| OpenVAS service | `asset_id + ip + port + protocol + oid/cve` |
| Secret | `asset_id + file_path + secret_type + fingerprint` |

### 16.2 Status Temuan

| Status | Keterangan |
|---|---|
| Open | Temuan baru dan belum ditindaklanjuti. |
| Assigned | Temuan sudah ditugaskan. |
| In Progress | Sedang diperbaiki. |
| Remediated | PIC menyatakan sudah diperbaiki. |
| Retest | Menunggu atau sedang dilakukan scan ulang. |
| Closed | Temuan tidak muncul lagi atau sudah disetujui selesai. |
| False Positive | Temuan divalidasi bukan vulnerability relevan. |
| Accepted Risk | Risiko diterima dengan justifikasi dan approval. |
| Reopened | Temuan lama muncul kembali. |

---

## 17. Risk Scoring

### 17.1 Faktor Penilaian

| Faktor | Bobot Awal |
|---|---:|
| Severity scanner | 35% |
| CVSS score | 20% |
| Asset criticality | 15% |
| Exposure | 10% |
| Exploitability / KEV / EPSS bila tersedia | 10% |
| Remediation status dan usia temuan | 10% |

### 17.2 Kategori Risk Score

| Risk Score | Kategori | SLA Rekomendasi |
|---:|---|---|
| 90–100 | Critical | 1–3 hari kerja. |
| 70–89 | High | Maksimal 7 hari kerja. |
| 40–69 | Medium | Maksimal 30 hari kerja. |
| 10–39 | Low | 60–90 hari kerja. |
| 0–9 | Informational | Sesuai kebutuhan. |

---

## 18. Workflow Operasional

### 18.1 Container/Image Scan

```text
User memilih asset container image
   → SATRIA menjalankan Trivy image scan
   → SATRIA menjalankan Syft generate SBOM
   → SATRIA menjalankan Grype terhadap SBOM/image
   → Raw report dan SBOM disimpan
   → Finding dinormalisasi dan didedup
   → Critical/high dikirim ke DFIR-IRIS
   → Developer melakukan remediation
   → SATRIA menjalankan retest
   → Finding ditutup bila tidak muncul kembali
```

### 18.2 Repository/Filesystem Scan

```text
User memilih repository atau folder source/build
   → SATRIA menjalankan Trivy repo/fs scan
   → SATRIA menjalankan Syft SBOM generation
   → SATRIA menjalankan Grype filesystem/SBOM scan
   → Raw report disimpan
   → Finding dinormalisasi
   → Secret/misconfiguration/CVE prioritas dikirim ke DFIR-IRIS
   → PIC melakukan perbaikan
   → Retest dilakukan
```

### 18.3 Server/IP Scan

```text
User memilih asset IP/server
   → SATRIA validasi whitelist target
   → SATRIA membuat task scan ke OpenVAS/Greenbone
   → OpenVAS menjalankan scan
   → SATRIA mengambil report
   → Parser OpenVAS memproses report
   → Finding dinormalisasi
   → Critical/high dikirim ke DFIR-IRIS
   → Sysadmin melakukan patching/hardening
   → Retest dilakukan
   → Case ditutup
```

### 18.4 Web/API Scan

```text
User memilih URL/API
   → SATRIA menjalankan ZAP baseline scan
   → Jika disetujui, SATRIA menjalankan ZAP full/API scan
   → Raw report disimpan
   → Finding web/API dinormalisasi
   → Finding prioritas dikirim ke DFIR-IRIS
   → Developer memperbaiki header/session/input validation/API
   → Retest ZAP
   → Finding ditutup
```

---

## 19. Kebutuhan Fungsional Detail

| Kode | Kebutuhan Fungsional |
|---|---|
| FR-01 | Platform dapat mencatat asset berupa aplikasi, server, IP, URL, API, repository, container image, filesystem, dan Kubernetes asset bila diperlukan. |
| FR-02 | Platform dapat menentukan scanner yang sesuai berdasarkan jenis asset dan scan profile. |
| FR-03 | Platform dapat menjalankan Trivy untuk image, repo, filesystem, config/IaC, secret, dan SBOM. |
| FR-04 | Platform dapat menjalankan Syft untuk membuat SBOM dari image dan filesystem. |
| FR-05 | Platform dapat menjalankan Grype untuk scan CVE dari image, filesystem, dan SBOM. |
| FR-06 | Platform dapat membuat dan menjalankan scan task pada OpenVAS/Greenbone untuk IP/server/network asset. |
| FR-07 | Platform dapat menjalankan OWASP ZAP baseline, full scan, dan API scan terhadap URL/API yang diizinkan. |
| FR-08 | Platform dapat menyimpan raw output scanner dalam object storage atau filesystem terproteksi. |
| FR-09 | Platform dapat melakukan parsing output scanner menjadi format finding internal. |
| FR-10 | Platform dapat melakukan normalisasi severity menjadi Critical, High, Medium, Low, Informational. |
| FR-11 | Platform dapat melakukan deduplikasi temuan lintas scanner. |
| FR-12 | Platform dapat menghitung risk score berdasarkan severity, CVSS, asset criticality, exposure, exploitability, dan usia temuan. |
| FR-13 | Platform dapat mengirim temuan tertentu ke DFIR-IRIS sebagai alert/case/task/evidence. |
| FR-14 | Platform dapat menampilkan dashboard severity, status remediation, SLA, tren temuan, dan risk per asset. |
| FR-15 | Platform dapat menghasilkan laporan PDF, Excel, Markdown, HTML, dan JSON export. |
| FR-16 | Platform dapat melakukan retest dan membandingkan hasil scan sebelum dan sesudah remediation. |
| FR-17 | Platform dapat mendukung assignment temuan ke PIC developer, sysadmin, atau security analyst. |
| FR-18 | Platform dapat mengelola status temuan: Open, Assigned, In Progress, Remediated, Retest, Closed, False Positive, Accepted Risk, Reopened. |
| FR-19 | Platform dapat menyediakan scheduler untuk scan berkala. |
| FR-20 | Platform dapat mencatat audit log seluruh aktivitas user, scan, perubahan status, dan pengiriman ke DFIR-IRIS. |
| FR-21 | Platform dapat mengatur whitelist active scan untuk ZAP full scan dan OpenVAS scan. |
| FR-22 | Platform dapat mengelola credential scanner secara aman. |
| FR-23 | Platform dapat menyimpan dan mengaitkan raw report sebagai evidence. |
| FR-24 | Platform dapat menampilkan relasi finding dengan IRIS alert/case/task. |
| FR-25 | Platform dapat menyediakan API internal untuk integrasi dengan sistem lain. |

---

## 20. Kebutuhan Non-Fungsional

| Kode | Aspek | Kebutuhan |
|---|---|---|
| NFR-01 | Security | Platform wajib menggunakan autentikasi dan role-based access control. |
| NFR-02 | Authorization | Pengguna hanya dapat melihat asset dan finding sesuai role/unit kewenangan. |
| NFR-03 | Auditability | Semua aktivitas scan, update status, assignment, export report, dan closure harus tercatat. |
| NFR-04 | Isolation | Scanner berjalan di container/worker terpisah. |
| NFR-05 | Scalability | Job scan menggunakan queue agar dapat diproses paralel dan tidak membebani backend. |
| NFR-06 | Reliability | Job scan memiliki status terstruktur: queued, running, completed, failed, cancelled. |
| NFR-07 | Secrets Management | Credential registry, Git, OpenVAS, ZAP auth context, dan DFIR-IRIS API key harus disimpan terenkripsi. |
| NFR-08 | Data Retention | Raw report dan history finding disimpan sesuai kebijakan retensi. |
| NFR-09 | Performance | Dashboard tetap responsif saat jumlah finding besar. |
| NFR-10 | Deployment | Platform dapat dijalankan dengan Docker Compose dan disiapkan untuk migrasi ke Kubernetes/OpenShift. |
| NFR-11 | Network Control | Active scanner seperti OpenVAS dan ZAP full scan harus dibatasi dengan whitelist target. |
| NFR-12 | Maintainability | Setiap scanner connector dibuat modular agar mudah diganti atau diperbarui. |
| NFR-13 | Observability | Setiap service memiliki log, healthcheck, dan status monitoring. |
| NFR-14 | Backup | Database dan object storage harus dapat dibackup dan direstore. |
| NFR-15 | Compliance | Raw evidence dan audit log harus mendukung kebutuhan review/pemeriksaan. |

---

## 21. Role Pengguna

| Role | Kewenangan |
|---|---|
| Admin | Mengelola user, role, scanner config, integration config, dan global settings. |
| Security Analyst | Menjalankan scan, validasi finding, mengirim case ke DFIR-IRIS, membuat laporan. |
| Pentester | Menjalankan scan sesuai scope, melihat evidence, melakukan retest. |
| Developer | Melihat finding aplikasi yang menjadi tanggung jawabnya dan mengupdate status remediation. |
| Sysadmin | Melihat finding server/IP yang menjadi tanggung jawabnya dan mengupdate status remediation. |
| Reviewer/Manager | Melihat dashboard, SLA, tren risiko, dan laporan. |
| Viewer | Melihat data terbatas sesuai kewenangan. |

---

## 22. Database Entity Utama

| Entity | Isi |
|---|---|
| `users` | Data user. |
| `roles` | Role dan permission. |
| `assets` | Data aplikasi/server/repo/image/URL/API. |
| `asset_owners` | Mapping asset dengan owner/PIC. |
| `scan_profiles` | Template scan. |
| `scan_jobs` | Data job scan. |
| `scan_targets` | Target spesifik scan. |
| `scan_results` | Metadata hasil scan. |
| `raw_reports` | Lokasi file JSON/XML/HTML/SBOM. |
| `findings` | Temuan hasil normalisasi. |
| `finding_evidences` | Evidence detail. |
| `finding_references` | Referensi CVE/advisory. |
| `remediation_tasks` | Tugas perbaikan. |
| `iris_mappings` | Relasi finding dengan alert/case/task DFIR-IRIS. |
| `scanner_configs` | Konfigurasi scanner. |
| `scheduler_jobs` | Jadwal scan berkala. |
| `audit_logs` | Log aktivitas. |

---

## 23. Dashboard yang Diperlukan

| Dashboard | Isi |
|---|---|
| Executive Dashboard | Total critical/high/medium/low, tren bulanan, top risky asset. |
| Asset Risk Dashboard | Risiko per aplikasi, server, repo, image, URL, dan API. |
| Scanner Dashboard | Hasil per scanner: Trivy, Syft, Grype, OpenVAS, ZAP. |
| Remediation Dashboard | Status open, assigned, in progress, retest, closed. |
| SLA Dashboard | Temuan melewati SLA dan umur temuan. |
| SBOM Dashboard | Daftar komponen software per aplikasi/image. |
| Web/API Security Dashboard | Header issue, XSS, injection, cookie/session issue, API finding. |
| Infrastructure VA Dashboard | Temuan server/IP/port/service. |
| Secret Exposure Dashboard | Potensi credential/token exposure dari Trivy. |
| DFIR-IRIS Integration Dashboard | Alert/case/task yang sudah dibuat di IRIS. |

---

## 24. Format Laporan

| Jenis Laporan | Target Pembaca | Isi |
|---|---|---|
| Executive Summary | Pimpinan/koordinator | Ringkasan risiko, tren, top asset, rekomendasi strategis. |
| Technical Report | Developer/sysadmin/security | Detail CVE, package, URL, port, evidence, rekomendasi. |
| Remediation Report | Koordinator/PIC | Status tindak lanjut, SLA, pending action, retest result. |
| SBOM Report | Security/compliance | Daftar komponen software dan dependency. |
| Evidence Pack | Auditor/security reviewer | Raw report, metadata scan, parser result, dan case mapping. |

---

## 25. Acceptance Criteria

| Kode | Acceptance Criteria |
|---|---|
| AC-01 | Docker Compose dapat menjalankan minimal SATRIA frontend, backend, database, queue, storage, dan worker scanner. |
| AC-02 | Pengguna dapat login dan mengakses dashboard sesuai role. |
| AC-03 | Pengguna dapat mendaftarkan asset berupa image, repo, IP/server, URL, dan API. |
| AC-04 | Pengguna dapat memilih scan profile sesuai jenis target. |
| AC-05 | Platform dapat menjalankan Trivy dan menyimpan hasil JSON. |
| AC-06 | Platform dapat menjalankan Syft dan menghasilkan SBOM. |
| AC-07 | Platform dapat menjalankan Grype terhadap image/filesystem/SBOM. |
| AC-08 | Platform dapat menjalankan ZAP baseline terhadap URL. |
| AC-09 | Platform dapat membuat scan task OpenVAS/Greenbone dan mengambil hasil scan. |
| AC-10 | Platform dapat menyimpan raw report ke storage. |
| AC-11 | Platform dapat menormalisasi hasil scanner ke tabel finding internal. |
| AC-12 | Platform dapat melakukan deduplikasi temuan. |
| AC-13 | Platform dapat menampilkan dashboard severity dan status remediation. |
| AC-14 | Platform dapat mengirim minimal finding Critical/High ke DFIR-IRIS sebagai alert/case. |
| AC-15 | Platform dapat menyimpan raw report sebagai evidence dan mengaitkannya dengan finding. |
| AC-16 | Platform dapat melakukan retest dan membandingkan status temuan. |
| AC-17 | Platform memiliki role minimal: Admin, Security Analyst, Developer/Sysadmin, Reviewer, Viewer. |
| AC-18 | Platform memiliki audit log aktivitas. |
| AC-19 | Platform dapat menghasilkan laporan PDF atau Excel. |
| AC-20 | Active scan ZAP/OpenVAS hanya dapat dijalankan terhadap target yang masuk whitelist. |

---

## 26. Tahapan Implementasi

### 26.1 Tahap 1 — MVP Docker Compose dan Scanner Dasar

| Fokus | Output |
|---|---|
| Docker Compose dasar | frontend, backend, database, queue, storage, worker. |
| Asset inventory | Data target tersimpan. |
| Integrasi Trivy | Image/repo/filesystem scan. |
| Integrasi Syft | SBOM generation. |
| Integrasi Grype | SBOM/image vulnerability scan. |
| Normalisasi finding awal | Tabel finding internal. |
| Dashboard severity | Critical/high/medium/low. |

### 26.2 Tahap 2 — Web/API dan Infrastructure Scan

| Fokus | Output |
|---|---|
| Integrasi OWASP ZAP | Web/API baseline scan. |
| Integrasi OpenVAS/Greenbone | IP/server scan. |
| Parsing hasil ZAP/OpenVAS | Finding web/API dan infra. |
| Whitelist active scan | Kontrol target aktif. |
| Raw evidence storage | JSON/XML/HTML tersimpan. |

### 26.3 Tahap 3 — DFIR-IRIS Case Management

| Fokus | Output |
|---|---|
| Integrasi DFIR-IRIS API | Finding masuk sebagai alert/case. |
| Mapping asset/finding/evidence | Case lebih lengkap. |
| Task remediation | Penugasan ke PIC. |
| Status mapping | Open/in progress/closed. |
| Retest workflow | Validasi perbaikan. |

### 26.4 Tahap 4 — Reporting dan Governance

| Fokus | Output |
|---|---|
| Executive dashboard | Ringkasan manajemen. |
| SLA remediation | Pantauan keterlambatan. |
| PDF/Excel report | Laporan formal. |
| Audit log | Jejak aktivitas. |
| Role-based access | Kontrol akses. |

### 26.5 Tahap 5 — Enterprise Readiness

| Fokus | Output |
|---|---|
| SSO/LDAP/OIDC | Integrasi akun internal. |
| Scheduler scan berkala | Scan otomatis periodik. |
| API integration | Integrasi Wazuh/SIEM/Jira jika diperlukan. |
| OpenShift/Kubernetes deployment | Deployment production-ready. |
| Policy engine | Gate berdasarkan severity. |

---

## 27. Risiko Implementasi dan Mitigasi

| Risiko | Dampak | Mitigasi |
|---|---|---|
| OpenVAS resource intensive | Server lambat saat scan besar | Batasi concurrency, gunakan schedule, segmentasi target. |
| ZAP full scan mengganggu aplikasi | Potensi beban/efek ke aplikasi | Default baseline scan, full scan hanya dengan approval. |
| Docker socket exposure | Risiko privilege escalation | Hindari jika memungkinkan; gunakan registry scan atau socket read-only dengan kontrol ketat. |
| Banyak false positive | Membebani tim remediation | Tambahkan validasi, accepted risk, false positive workflow. |
| Duplikasi CVE dari Trivy dan Grype | Dashboard tidak akurat | Terapkan deduplication key. |
| Credential scanner bocor | Risiko keamanan tinggi | Gunakan encrypted secret, RBAC, audit log. |
| Raw report berisi informasi sensitif | Risiko kebocoran data | Batasi akses evidence, enkripsi storage, retention policy. |
| Integrasi API berubah | Connector gagal | Buat adapter modular dan versioned API client. |

---

## 28. Catatan Desain untuk Tim Pengembang

1. Platform SATRIA adalah **orchestrator**, bukan pengganti scanner.
2. Trivy, Syft, dan Grype dapat digabung dalam satu worker container pada tahap awal.
3. OWASP ZAP sebaiknya tetap container tersendiri.
4. OpenVAS/Greenbone sebaiknya dijalankan menggunakan pola container/compose resmi karena terdiri dari beberapa service.
5. DFIR-IRIS sebaiknya dijalankan sesuai pola Docker Compose resminya dan diintegrasikan melalui API.
6. SATRIA tetap memerlukan database sendiri untuk normalisasi, deduplikasi, risk scoring, dashboard, dan histori scan.
7. DFIR-IRIS digunakan sebagai case/ticket layer, bukan sebagai database utama vulnerability.
8. Raw scanner output wajib disimpan sebagai evidence.
9. Active scan harus dikendalikan dengan whitelist, approval, dan audit log.
10. Scanner connector harus modular agar mudah diperbarui tanpa mengubah core aplikasi.

---

## 29. Rumusan Final

Platform SATRIA dikembangkan sebagai **satu Docker Compose environment** yang terdiri atas SATRIA frontend, backend, database, queue, storage, scanner workers, OpenVAS/Greenbone, OWASP ZAP, dan DFIR-IRIS. Platform ini berfungsi sebagai security assessment dan remediation tracking platform yang menerima target berupa container image, source repository, filesystem, server/IP, web application, dan API; menjalankan scanner yang sesuai; mengumpulkan raw output; menormalisasi dan mendeduplikasi temuan; menghitung risk score; menampilkan dashboard; menghasilkan laporan; serta mengirim temuan prioritas ke DFIR-IRIS sebagai alert, case, task, dan evidence untuk proses remediation, retest, dan closure.

---

## 30. Lampiran — Source Link yang Digunakan

1. Syft-Grype: https://github.com/Syft-Grype
2. Anchore Syft: https://github.com/anchore/syft
3. Anchore Grype: https://github.com/anchore/grype
4. Greenbone OpenVAS Scanner: https://github.com/greenbone/openvas-scanner
5. Greenbone Community Containers: https://greenbone.github.io/docs/latest/22.4/container/index.html
6. Aqua Security Trivy: https://github.com/aquasecurity/trivy
7. OWASP ZAP: https://github.com/zaproxy/zaproxy
8. DFIR-IRIS: https://github.com/dfir-iris/iris-web
9. DFIR-IRIS Getting Started: https://docs.dfir-iris.org/latest/getting_started/
10. Docker Compose Services Reference: https://docs.docker.com/reference/compose-file/services/
