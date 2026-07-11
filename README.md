# SATRIA

<p align="center">
  <img src="app/static/logo.png" alt="Logo SATRIA" width="220">
</p>

<p align="center">
  <strong>Security Assessment, Tracking, Remediation, and Incident Automation</strong><br>
  Panel orkestrasi pemindaian keamanan yang menyatukan registrasi aset, eksekusi scan, prioritisasi temuan, keputusan gate, dan monitoring ticket DFIR-IRIS dalam satu dashboard operasional.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Backend-FastAPI-009688" alt="FastAPI">
  <img src="https://img.shields.io/badge/Frontend-HTML%20%2B%20CSS%20%2B%20JS-1E88E5" alt="Frontend">
  <img src="https://img.shields.io/badge/Runtime-Docker%20Compose-FB8C00" alt="Docker Compose">
  <img src="https://img.shields.io/badge/Scanning-Trivy%20%7C%20Syft%20%7C%20Grype%20%7C%20ZAP%20%7C%20OpenVAS-3949AB" alt="Scanning Engines">
  <img src="https://img.shields.io/badge/Ticketing-DFIR--IRIS-5E35B1" alt="DFIR-IRIS">
  <img src="https://img.shields.io/badge/Mode-SOC%20Operations-1565C0" alt="SOC Operations">
</p>

---

## Overview

Repository ini dibuat sebagai panel orkestrasi keamanan untuk tim operasional yang perlu:

- mendaftarkan aset dari berbagai jenis target;
- menjalankan scan dengan engine yang berbeda dari satu panel;
- membaca hasil dalam bentuk severity, risk score, dan status tindak lanjut;
- memutuskan apakah artefak atau target `allowed`, `need_approval`, atau `blocked`;
- mengirim temuan prioritas ke DFIR-IRIS tanpa memindahkan operator ke workflow lain;
- memonitor case IRIS secara read-only dari SATRIA.

SATRIA tidak menggantikan scanner yang sudah ada. Perannya adalah menghubungkan engine seperti Trivy, Syft, Grype, ZAP, dan OpenVAS ke panel kerja yang mudah dipakai operator SOC, tim pengembang, dan pengambil keputusan.

---

## Cocok Untuk Siapa

Platform ini cocok untuk:

- operator SOC yang perlu satu panel untuk scan, triase, dan ticket monitoring;
- tim DevSecOps yang ingin menempatkan security gate sebelum artefak masuk staging atau production;
- analis keamanan yang perlu memonitor temuan dan status case IRIS dari satu tempat;
- pimpinan teknis yang membutuhkan ringkasan kondisi aset, finding, dan eskalasi.

---

## Posisi Dalam Ekosistem

Dalam ekosistem kerja SITP saat ini:

- `PANAH` berfokus pada assessment teknis, simulasi eksekusi, dan review evidence.
- `SATRIA` berfokus pada registrasi aset, orkestrasi scan, pembacaan hasil, dan keputusan operasional.
- `PERISAI` atau DFIR-IRIS berfokus pada case management, task, activity log, evidence, dan investigasi insiden lanjutan.

Dengan pola ini, SATRIA menjadi jembatan antara assessment teknis dan ticketing formal.

---

## Fitur Utama

- Registrasi aset multi-target untuk `container_image`, `web_application`, `server_ip`, `source_repository`, `filesystem`, `api_endpoint`, dan target lain yang sudah dipetakan ke profile scan.
- Wizard operasional berbasis step agar operator mengikuti urutan kerja yang konsisten.
- Scan orchestration untuk Trivy, Syft, Grype, ZAP, dan OpenVAS dari satu panel.
- Scan history, retry job, cleanup lokal, dan detail eksekusi per scan.
- Findings view dengan filter otomatis, severity donut, risk summary, dan prioritas temuan.
- Ticket publish ke DFIR-IRIS untuk temuan prioritas, plus monitoring status case dari SATRIA.
- Reports dan analytics untuk ringkasan scan, exposure aset, severity, status finding, dan status case IRIS.
- SOP kontekstual pada menu Assets, termasuk panduan pipeline CI/CD.
- Admin token / service account untuk integrasi pipeline.
- Gate policy untuk keputusan `allowed`, `need_approval`, dan `blocked`.

---

## Menu Operasional

- `Overview`
  Menampilkan ringkasan aset aktif, scan jobs, findings, exposure aset, dan jalur kerja operator.

- `Assets`
  Digunakan untuk menambah, mengubah, dan menghapus aset; membuka SOP tambah aset; membuka panduan interkoneksi CI/CD; serta mengelola allowlist atau gate terkait jenis target.

- `Scans`
  Digunakan untuk menjalankan scan, melihat riwayat job, membuka detail eksekusi, retry scan, dan membersihkan data lokal yang sudah tidak relevan.

- `Findings`
  Menampilkan daftar temuan berdasarkan severity, aset, scanner, status, dan prioritas risiko. Dari sini operator dapat membuka detail temuan dan mempublish tiket ke IRIS.

- `Tickets`
  Menjadi panel monitoring case DFIR-IRIS dari SATRIA, baik yang berasal dari temuan SATRIA maupun sinkronisasi ticket manual dari IRIS sesuai konfigurasi integrasi.

- `Reports`
  Menyediakan ringkasan analitik, export CSV/Excel, dan representasi visual exposure, severity, serta distribusi status case di IRIS.

- `API Docs`
  Menyediakan referensi endpoint untuk interkoneksi automation, pipeline, dan service account.

- `Admin Token`
  Menyediakan pengelolaan service account pipeline untuk API key dan scope integrasi.

- `Gate Policy`
  Menyediakan pengaturan aturan kebijakan yang menentukan keputusan gate seperti `allowed`, `need_approval`, atau `blocked`.

---

## Engine Yang Diorkestrasi

- `Syft`
  Inventaris komponen software atau SBOM.

- `Grype`
  Pemeriksaan CVE terhadap dependency atau komponen software.

- `Trivy`
  Scanner serbaguna untuk image, repository, IaC, dan secret.

- `ZAP`
  Scanner keamanan aplikasi web.

- `OpenVAS`
  Scanner keamanan host atau jaringan.

---

## Konsep Kerja

Alur kerja SATRIA dirancang sederhana namun operasional:

1. aset didaftarkan sesuai tipe target;
2. operator memilih profile scan yang sesuai konteks;
3. SATRIA menjalankan engine yang relevan;
4. hasil dibaca menjadi finding yang lebih mudah ditindaklanjuti;
5. dashboard menampilkan severity, risk score, status, dan exposure;
6. bila perlu, temuan dipublish ke DFIR-IRIS;
7. SATRIA hanya memonitor status ticket dari IRIS tanpa menduplikasi workflow investigasi.

Dengan pola ini, operator tidak perlu berpindah-pindah antara alat teknis, spreadsheet, dan sistem ticketing.

---

## Dukungan CI/CD Security Gate

SATRIA sudah disiapkan untuk diposisikan sebagai `security gate` pada jalur build-release.

Pola minimum yang didukung:

1. pipeline build artefak atau image;
2. pipeline push ke registry;
3. pipeline mengirim `release intake` ke SATRIA;
4. SATRIA membuat scan job berbasis profile yang disetujui;
5. pipeline melakukan polling status;
6. SATRIA mengembalikan hasil dan keputusan:
   - `allowed`
   - `need_approval`
   - `blocked`
7. bila perlu, SATRIA meneruskan temuan prioritas ke IRIS.

Endpoint minimum yang tersedia:

- `POST /api/v1/releases/intake`
- `POST /api/v1/scans`
- `GET /api/v1/scans/{scan_id}`
- `GET /api/v1/scans/{scan_id}/result`
- `POST /api/v1/scans/{scan_id}/publish-ticket`

Fitur integrasi yang sudah ada:

- service account pipeline;
- API key berbasis scope;
- gate policy;
- demo gate `passed` dan `failed`;
- dokumentasi Jenkins server dan Jenkins lokal untuk uji koneksi ke SATRIA.

Panduan rinci ada di:

- [docs/jenkins-local-satria-scenario.md](C:\Users\gufroni\Documents\GitHub\satria\docs\jenkins-local-satria-scenario.md)
- [infra/jenkins-local/README.md](C:\Users\gufroni\Documents\GitHub\satria\infra\jenkins-local\README.md)
- [docs/AUDIT-UR-CICD-SATRIA-2026-07-04.md](C:\Users\gufroni\Documents\GitHub\satria\docs\AUDIT-UR-CICD-SATRIA-2026-07-04.md)
- [docs/SOP-HULU-HILIR-PER-TIM.md](C:\Users\gufroni\Documents\GitHub\satria\docs\SOP-HULU-HILIR-PER-TIM.md)

---

## Integrasi Dengan DFIR-IRIS

SATRIA terhubung ke DFIR-IRIS untuk kebutuhan ticketing formal.

Fungsi integrasi yang tersedia:

- publish temuan dari SATRIA ke IRIS sebagai case;
- monitoring status case IRIS dari SATRIA;
- refresh status remote dari IRIS;
- sinkronisasi ticket manual IRIS agar tetap terpantau di SATRIA sesuai konfigurasi integrasi;
- penerimaan alert Wazuh ke PERISAI/DFIR-IRIS melalui integration script Wazuh;
- pembacaan statistik status case seperti `Open`, `Assigned`, `In Progress`, `Closed`, dan lainnya.

Prinsip yang dipakai:

- workflow investigasi utama tetap berada di IRIS;
- SATRIA dipakai untuk orkestrasi scan, prioritisasi, dan monitoring integrasi;
- SATRIA bersifat read-only terhadap workflow case IRIS kecuali pada aksi publish ticket.

Panduan integrasi Wazuh ke PERISAI tersedia di [docs/INTEGRASI-WAZUH-PERISAI.md](C:\Users\gufroni\Documents\GitHub\satria\docs\INTEGRASI-WAZUH-PERISAI.md).

---

## Struktur Repository

```text
satria/
|-- app/
|   |-- api/
|   |-- core/
|   |-- static/
|   |-- templates/
|   `-- ...
|-- docs/
|-- infra/
|   |-- dfir-iris/
|   |-- greenbone/
|   `-- jenkins-local/
|-- scripts/
|-- tools/
|-- docker-compose.yml
|-- Dockerfile
|-- Makefile
|-- requirements.txt
`-- README.md
```

Ringkasnya:

- `app/` memuat backend, template, static asset, scanner orchestration, dan integrasi utama SATRIA.
- `docs/` memuat SOP, walkthrough top management, skenario IRIS, audit UR, dan panduan operasional.
- `infra/dfir-iris/` memuat komponen integrasi dan deployment DFIR-IRIS.
- `infra/greenbone/` memuat komponen terkait OpenVAS/Greenbone.
- `infra/jenkins-local/` memuat Jenkins lokal untuk uji pipeline.
- `scripts/` memuat utilitas operasional tambahan.

---

## Kebutuhan Lingkungan

Minimum yang disarankan:

- Docker Engine
- Docker Compose plugin
- Git
- Port `8090` untuk SATRIA lokal
- Resource tambahan jika OpenVAS dan IRIS dijalankan dalam host yang sama

Jika ingin menguji pipeline secara lokal:

- port `8088` untuk Jenkins lokal

---

## Quick Start

Di root repository:

```powershell
docker compose up -d --build
```

Setelah stack aktif:

- aplikasi lokal: [http://localhost:8090](http://localhost:8090)
- health check: [http://localhost:8090/health](http://localhost:8090/health)

Untuk stop stack:

```powershell
docker compose down
```

Untuk melihat log:

```powershell
docker compose logs -f
```

---

## Jenkins Untuk Uji Pipeline

Repository ini menyediakan dua pola uji Jenkins untuk simulasi interkoneksi ke SATRIA.

Endpoint operasional yang disarankan:

- Jenkins server: [http://10.216.83.114:8088](http://10.216.83.114:8088)
- job utama: `satria-security-gate`
- job demo lolos: `satria-gate-passed-demo`
- job demo gagal: `satria-gate-failed-demo`

Endpoint lokal untuk pengembangan:

- Jenkins lokal: [http://localhost:8088](http://localhost:8088)

Skenario yang sudah disiapkan:

- intake release ke SATRIA;
- create scan job;
- polling result;
- gate decision `passed`;
- gate decision `failed`;
- publish ticket opsional.

---

## Dokumen Yang Disarankan Dibaca Tim

- [docs/OPERASIONAL-SOC.md](C:\Users\gufroni\Documents\GitHub\satria\docs\OPERASIONAL-SOC.md)
- [docs/SOP-HULU-HILIR-PER-TIM.md](C:\Users\gufroni\Documents\GitHub\satria\docs\SOP-HULU-HILIR-PER-TIM.md)
- [docs/IRIS-TOP-MANAGEMENT-WALKTHROUGH.md](C:\Users\gufroni\Documents\GitHub\satria\docs\IRIS-TOP-MANAGEMENT-WALKTHROUGH.md)
- [docs/soc-iris-demo.md](C:\Users\gufroni\Documents\GitHub\satria\docs\soc-iris-demo.md)
- [docs/INTEGRASI-WAZUH-PERISAI.md](C:\Users\gufroni\Documents\GitHub\satria\docs\INTEGRASI-WAZUH-PERISAI.md)
- [docs/SMOKE-TEST-RESULTS.md](C:\Users\gufroni\Documents\GitHub\satria\docs\SMOKE-TEST-RESULTS.md)
- [docs/jenkins-local-satria-scenario.md](C:\Users\gufroni\Documents\GitHub\satria\docs\jenkins-local-satria-scenario.md)
- [infra/jenkins-local/README.md](C:\Users\gufroni\Documents\GitHub\satria\infra\jenkins-local\README.md)

---

## Status Implementasi Saat Ini

Kemampuan yang sudah tersedia pada iterasi saat ini:

- asset registration multi-target;
- SOP operasional berbasis halaman Assets dan Asset SOP;
- findings, risk summary, dan filter otomatis;
- publish ticket ke IRIS;
- ticket monitoring dari IRIS;
- service account dan API key untuk pipeline;
- gate policy dan gate decision;
- Jenkins lokal untuk uji interkoneksi;
- landing page ekosistem untuk PANAH, SATRIA, dan PERISAI.

Catatan yang masih perlu diperhatikan pada pengembangan lanjutan:

- aturan gate bisa terus diperkaya per environment atau per jenis target;
- arsip artefak pipeline dapat diperluas untuk retensi dan audit trail;
- integrasi approval formal dapat diperdalam bila ingin menjadi mandatory gate sebelum production release.

---

## Catatan Penggunaan

- Gunakan SATRIA sebagai panel orkestrasi dan monitoring, bukan pengganti analisis manual.
- Pastikan tipe target dan profile scan dipilih dengan benar agar hasil tidak bias.
- Gunakan publish ke IRIS hanya untuk finding yang memang perlu dilacak secara formal.
- Untuk pipeline, pastikan API key dibatasi dengan scope minimum yang diperlukan.

---

<p align="center">
  developed with love by cakgup
</p>
