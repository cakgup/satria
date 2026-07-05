# Audit UR Interkoneksi CI/CD SATRIA

Tanggal audit: `2026-07-04`

## Tujuan audit

Dokumen ini merangkum hasil audit implementasi SATRIA terhadap kebutuhan interkoneksi CI/CD, sekaligus mencatat bukti smoke test yang sudah dijalankan pada lingkungan lokal pengembangan.

## Ruang lingkup yang diuji

- Ketersediaan endpoint integrasi pipeline.
- Kemampuan Jenkins lokal memanggil SATRIA.
- Intake release artefak image.
- Pembuatan scan job dari pipeline.
- Polling status dan pembacaan hasil JSON.
- Keputusan gate pada pipeline.
- Kesiapan dokumentasi operasional untuk tim pengembang.

## Ringkasan hasil

Status umum: `Memenuhi mayoritas kebutuhan inti UR untuk fase MVP dan uji integrasi`

## Bukti teknis yang tervalidasi

### 1. Health check backend

- Endpoint `GET /health` merespons `status=ok`.

### 2. Kontrak API pipeline tersedia

Endpoint yang terverifikasi tersedia pada backend:

- `POST /api/v1/releases/intake`
- `POST /api/v1/scans`
- `GET /api/v1/scans/{scan_id}`
- `GET /api/v1/scans/{scan_id}/result`
- `POST /api/v1/scans/{scan_id}/publish-ticket`

### 3. Intake release berhasil

Pengujian `POST /api/v1/releases/intake` berhasil membuat release intake baru dengan contoh:

- `asset_code=UR-CHECK`
- `asset_name=UR Check Service`
- `image_ref=nginx:latest`
- `environment_target=staging`

Response mengembalikan:

- `asset_id`
- `release_id`
- `requested_by`
- metadata release lain

### 4. Smoke test Jenkins ke SATRIA berhasil

Job yang diuji:

- `satria-security-gate`

Parameter uji:

- `IMAGE_REF=nginx:latest`
- `ASSET_CODE=JENKINS-DEMO`
- `ASSET_NAME=Jenkins-Demo-Service`
- `SCAN_PROFILE=quick_container`
- `ENVIRONMENT_TARGET=staging`
- `PUBLISH_TO_IRIS=false`

Tahap yang berhasil:

1. Jenkins membuat `release-intake.json`.
2. Jenkins memanggil intake release ke SATRIA.
3. SATRIA mengembalikan `asset_id` dan `release_id`.
4. Jenkins membuat scan job SATRIA.
5. SATRIA mengembalikan `scan_id`.
6. Jenkins polling status sampai `completed`.
7. Jenkins mengambil hasil scan JSON.
8. Jenkins membaca `decision=blocked`.
9. Pipeline berhenti sesuai aturan gate.

### 5. Hasil gate terbukti berjalan

Pada build terbaru:

- `scan_id=18`
- `status=completed`
- `mode=real`
- `gate_decision=blocked`
- `policy_name=default-production-container-gate`
- total temuan `372`
- severity:
  - critical `2`
  - high `39`
  - medium `118`
  - low `142`
  - informational `71`

Makna hasil:

- Integrasi CI/CD ke SATRIA berjalan dengan baik.
- Yang gagal adalah release karena diblokir policy, bukan kegagalan koneksi antar sistem.

## Penilaian terhadap kebutuhan UR

### Sudah terpenuhi

- SATRIA dapat menerima metadata release dari pipeline.
- SATRIA dapat membuat scan job berbasis artefak image.
- Pipeline dapat membaca `scan_id` dan memantau status scan.
- Pipeline dapat membaca hasil JSON secara terstruktur.
- Pipeline dapat mengambil keputusan `allowed`, `need_approval`, atau `blocked`.
- SATRIA sudah memiliki halaman SOP untuk interkoneksi CI/CD.
- Jenkins lokal untuk pengujian sudah tersedia dan berjalan.

### Terpenuhi sebagian

- Publish tiket ke IRIS sudah tersedia melalui endpoint, tetapi smoke test kali ini difokuskan pada gate tanpa publish.
- Dokumentasi CI/CD di UI SATRIA sudah rinci, namun tetap perlu disosialisasikan ke tim DevOps agar implementasi per project konsisten.

### Belum sepenuhnya terpenuhi atau masih perlu penguatan

- Self-service API key dari UI SATRIA belum tersedia; token masih dikelola oleh administrator backend.
- Artefak pipeline pada build yang diblokir belum selalu terarsip otomatis pada semua kondisi.
- Belum ada template Jenkins shared library atau plugin khusus; saat ini masih berbasis Jenkinsfile dan curl/API.

## Risiko implementasi saat masuk produksi

- Jika token pipeline dipakai bersama oleh terlalu banyak aplikasi, audit trail bisa kurang spesifik.
- Jika registry internal tidak dapat diakses SATRIA, scan akan gagal walau pipeline berhasil build dan push.
- Jika threshold gate tidak disepakati lintas tim, keputusan `blocked` dapat dianggap sebagai bug padahal sebenarnya kebijakan.
- Jika publish ticket ke IRIS diaktifkan tanpa severity filter, jumlah case dapat melonjak terlalu banyak.

## Rekomendasi tindak lanjut

1. Pisahkan service account pipeline per domain aplikasi atau per lini produk.
2. Tambahkan dokumentasi approval path untuk `need_approval`.
3. Implementasikan arsip artefak pipeline yang selalu berjalan pada stage `post`.
4. Tambahkan smoke test otomatis berkala untuk endpoint integrasi.
5. Siapkan template Jenkinsfile dan `.gitlab-ci.yml` resmi per standar organisasi.

## Kesimpulan

Secara fungsional, SATRIA sudah mampu memenuhi kebutuhan inti UR interkoneksi CI/CD untuk fase MVP:

- menerima intake release
- menjalankan scan artefak image
- mengembalikan keputusan gate
- menghentikan release yang tidak lolos
- menyiapkan jalur publish ke IRIS

Dengan kata lain, SATRIA sudah layak dipakai sebagai `security gate` awal pada jalur build-release, dengan catatan penguatan berikutnya berfokus pada hardening operasional, manajemen token, dan penyempurnaan artefak pipeline.
