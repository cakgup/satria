# SATRIA

Security Assessment, Tracking, Remediation, and Incident Automation.

SATRIA adalah platform orkestrasi pemindaian keamanan yang memusatkan pendaftaran aset, eksekusi scan, pembacaan hasil, prioritisasi temuan, dan pengiriman tiket ke DFIR-IRIS dalam satu alur operasional. Fokus utamanya bukan menggantikan scanner yang sudah ada, tetapi menghubungkan engine seperti Trivy, Syft, Grype, ZAP, dan OpenVAS ke panel kerja yang mudah dipakai operator, tim pengembang, dan pengambil keputusan.

## Fungsi utama

- Registrasi aset untuk berbagai tipe target seperti `container_image`, `web_application`, `server_ip`, `source_repository`, `filesystem`, dan `api_endpoint`.
- Orkestrasi scan dengan profile yang disesuaikan terhadap konteks target.
- Pembacaan hasil scan dalam bentuk severity, risk score, dan status tindak lanjut.
- Gate keputusan untuk kebutuhan release, misalnya `allowed`, `need_approval`, atau `blocked`.
- Publish tiket ke IRIS untuk temuan yang membutuhkan pelacakan resmi.
- Monitoring status tiket IRIS dari SATRIA secara read-only.
- Dukungan SOP operasional agar tim teknis memiliki pola kerja yang konsisten.

## Posisi SATRIA dalam ekosistem

Dalam ekosistem kerja SITP saat ini:

- `PANAH` berperan pada otomasi assessment teknis dan simulasi eksekusi.
- `SATRIA` berperan pada orkestrasi aset, pemindaian, pengambilan keputusan, dan pengiriman tiket.
- `PERISAI` atau IRIS berperan pada workflow case, task, evidence, dan investigasi insiden lanjutan.

## Menu operasional utama

- `Overview`: ringkasan kondisi aset, scan, finding, dan jalur kerja operator.
- `Assets`: pendaftaran aset dan panduan target yang benar.
- `Scans`: riwayat job, detail eksekusi, retry, dan cleanup lokal.
- `Findings`: daftar temuan dengan filter severity, aset, scanner, dan status.
- `Tickets`: monitoring integrasi case dari IRIS tanpa menduplikasi workflow ticketing.
- `Reports`: rekap analitik, ekspor, dan bulk action.
- `API Docs`: referensi endpoint untuk integrasi pipeline dan otomasi.

## Engine yang diorkestrasi

- `Syft`: inventaris komponen software atau SBOM.
- `Grype`: deteksi CVE dari dependency atau komponen software.
- `Trivy`: scanner serbaguna untuk image, repository, IaC, dan secret.
- `ZAP`: scanner keamanan aplikasi web.
- `OpenVAS`: scanner keamanan host atau jaringan.

## Alur kerja operasional

1. Daftarkan aset sesuai tipe target.
2. Jalankan scan dengan profile yang relevan.
3. Tinjau hasil dan prioritas risikonya.
4. Putuskan apakah release boleh lanjut, perlu approval, atau harus diblokir.
5. Publish tiket ke IRIS bila temuan membutuhkan pelacakan formal.
6. Pantau status case IRIS dari menu Tickets di SATRIA.

## Dukungan interkoneksi CI/CD

SATRIA sudah disiapkan untuk diposisikan sebagai `security gate` pada pipeline build-release. Alur integrasinya:

1. Pipeline build dan push image ke registry.
2. Pipeline mengirim intake release ke SATRIA.
3. SATRIA membuat scan job berdasarkan profile yang disetujui.
4. Pipeline melakukan polling status dan mengambil result JSON.
5. Pipeline membaca keputusan `allowed`, `need_approval`, atau `blocked`.
6. Bila diperlukan, SATRIA dapat mempublish temuan berat ke IRIS.

Endpoint minimum yang tersedia:

- `POST /api/v1/releases/intake`
- `POST /api/v1/scans`
- `GET /api/v1/scans/{scan_id}`
- `GET /api/v1/scans/{scan_id}/result`
- `POST /api/v1/scans/{scan_id}/publish-ticket`

Panduan rinci ada di:

- [docs/jenkins-local-satria-scenario.md](C:\Users\gufroni\Documents\GitHub\satria\docs\jenkins-local-satria-scenario.md)
- [infra/jenkins-local/README.md](C:\Users\gufroni\Documents\GitHub\satria\infra\jenkins-local\README.md)

## Menjalankan secara lokal

Prasyarat:

- Docker dan Docker Compose aktif.
- Port `8090` tersedia untuk backend SATRIA lokal.

Perintah dasar:

```powershell
docker compose up -d --build
```

Setelah stack aktif:

- Aplikasi: [http://localhost:8090](http://localhost:8090)
- Health check: [http://localhost:8090/health](http://localhost:8090/health)

## Jenkins lokal untuk uji pipeline

Repository ini juga menyediakan Jenkins lokal berbasis Docker pada:

- Jenkins UI: [http://localhost:8088](http://localhost:8088)
- Job contoh: `satria-security-gate`

Job tersebut sudah disiapkan untuk menguji alur:

- intake release
- create scan
- polling result
- gate decision
- publish ticket opsional

## Status implementasi saat ini

Smoke test integrasi Jenkins -> SATRIA yang sudah terbukti berjalan:

- intake release berhasil
- create scan job berhasil
- polling status berhasil
- hasil JSON scan berhasil dibaca pipeline
- keputusan gate `blocked` berhasil menghentikan release

Catatan yang masih perlu diperhatikan:

- API key pipeline saat ini masih dikelola oleh administrator melalui environment backend, belum self-service dari UI.
- Bila build diblokir, artefak pipeline belum selalu terarsip otomatis pada semua kasus; ini dapat diperbaiki pada iterasi berikutnya dengan `post { always { ... } }` yang aman.

## Struktur direktori penting

- [`app/`](C:\Users\gufroni\Documents\GitHub\satria\app): backend, template, static asset, dan workflow utama SATRIA.
- [`docs/`](C:\Users\gufroni\Documents\GitHub\satria\docs): dokumentasi operasional, walkthrough, dan skenario integrasi.
- [`infra/jenkins-local/`](C:\Users\gufroni\Documents\GitHub\satria\infra\jenkins-local): Jenkins lokal untuk uji interkoneksi CI/CD.
- [`scripts/`](C:\Users\gufroni\Documents\GitHub\satria\scripts): utilitas operasional tambahan.

## Dokumen yang direkomendasikan dibaca tim

- [docs/jenkins-local-satria-scenario.md](C:\Users\gufroni\Documents\GitHub\satria\docs\jenkins-local-satria-scenario.md)
- [docs/AUDIT-UR-CICD-SATRIA-2026-07-04.md](C:\Users\gufroni\Documents\GitHub\satria\docs\AUDIT-UR-CICD-SATRIA-2026-07-04.md)
- [infra/jenkins-local/README.md](C:\Users\gufroni\Documents\GitHub\satria\infra\jenkins-local\README.md)
