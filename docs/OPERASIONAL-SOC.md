# SATRIA Operasional Teknis dan SOC

## Navigasi Dokumen Terkait

- [Indeks dokumentasi SATRIA](C:/Users/gufroni/Documents/GitHub/satria/docs/README.md)
- [SOP Hulu-Hilir Per Tim](C:/Users/gufroni/Documents/GitHub/satria/docs/SOP-HULU-HILIR-PER-TIM.md)
- [Walkthrough IRIS untuk Top Management](C:/Users/gufroni/Documents/GitHub/satria/docs/IRIS-TOP-MANAGEMENT-WALKTHROUGH.md)
- [Integrasi Wazuh ke PERISAI](C:/Users/gufroni/Documents/GitHub/satria/docs/INTEGRASI-WAZUH-PERISAI.md)

Dokumen ini menjelaskan alur kerja SATRIA dari sisi operator teknis dan tim SOC agar penggunaan harian konsisten, mudah dipahami, dan tidak salah memilih jenis asset atau profile scan.

## Prinsip Utama

- SATRIA adalah layer orkestrasi scan, normalisasi finding, prioritisasi, dan penghubung ke DFIR-IRIS.
- DFIR-IRIS adalah sistem ticketing utama untuk case, task, timeline, dan evidence.
- SATRIA menyimpan raw report scanner, hasil normalisasi, risk score, dan mirror status case untuk monitoring cepat.

## Urutan Operasional Harian

1. Daftarkan asset di menu `Assets`.
2. Jalankan scan dari menu `New Scan`.
3. Pantau status di menu `Scans`.
4. Review dan validasi temuan di menu `Findings`.
5. Kirim finding prioritas ke IRIS.
6. Pantau status sinkronisasi dan case remote di menu `Tickets`.
7. Lakukan update task, evidence, dan closure utama di IRIS.

## Pemetaan Menu

- `Overview`: ringkasan singkat kondisi asset, scan, finding, dan antrian kerja.
- `Assets`: inventory target scan aktif.
- `Scans`: riwayat job scan dan status eksekusinya.
- `Findings`: daftar temuan yang sudah dinormalisasi dan diprioritaskan.
- `Tickets`: monitoring case DFIR-IRIS, termasuk case yang gagal publish agar bisa diretry.
- `Reports`: ringkasan eksekutif, export CSV/Excel, dan bulk action Critical/High.
- `New Scan`: shortcut untuk membuat scan job baru.

## Cara Memilih Jenis Asset

### 1. Container image

Gunakan bila yang ingin diperiksa adalah image build atau image deploy.

- Contoh target: `nginx:latest`
- Contoh target: `registry.internal/app-sakti:2026.07.01`
- Scanner yang umum: `quick_container`, `sbom_scan`, `full_container`

Catatan teknis:

- Container image tidak harus dijalankan dengan `docker compose up`.
- Image harus tersedia atau dapat diakses dari host tempat worker SATRIA berjalan.
- Untuk `syft` dan `grype`, SATRIA membaca target sebagai `docker:<image>` bila target berupa image lokal/registry biasa.

### 2. Source repository

Gunakan bila yang ingin diperiksa adalah source code repository.

- Contoh target: `https://git.internal/repo/app`
- Scanner yang umum: `repo_security`

### 3. Filesystem

Gunakan bila yang ingin diperiksa adalah folder atau path lokal yang bisa diakses worker SATRIA.

- Contoh target: `/data/source/app`
- Scanner yang umum: `repo_security`

### 4. Server / IP

Gunakan untuk host, server, atau alamat IP yang akan diuji dengan Greenbone/OpenVAS.

- Contoh target: `<server-ip>`

Catatan keamanan:

- gunakan placeholder pada SOP dan dokumentasi;
- nilai IP aktual hanya dibaca dari inventaris aset atau CMDB internal.
- Scanner yang umum: `infra_va`

Catatan teknis:

- Target harus masuk allowlist.
- SATRIA harus terhubung ke `gvmd` OpenVAS/Greenbone.

### 5. Web application atau API endpoint

Gunakan untuk URL aplikasi web atau endpoint API yang ingin diuji dengan ZAP.

- Contoh target: `https://app.internal.go.id`
- Scanner yang umum: `web_baseline`, `web_full`

Catatan teknis:

- `web_baseline` untuk scan pasif/baseline.
- `web_full` untuk active scan dan harus dipakai hanya untuk target yang sudah diizinkan.

## Alur Teknis di Belakang Layar

1. User membuat asset.
2. User membuat scan job.
3. SATRIA worker memilih scanner berdasarkan profile.
4. Scanner menghasilkan raw report JSON/XML.
5. SATRIA menormalisasi hasil ke model finding yang seragam.
6. SATRIA menghitung severity terstandar dan risk score.
7. Finding tampil di dashboard, findings, dan reports.
8. Saat operator menekan `Create Ticket` atau bulk send, SATRIA membuat case mirror lokal lalu sinkron ke IRIS.
9. Jika publish berhasil, SATRIA menyimpan `remote_case_id`, `remote_alert_id`, task, dan evidence mapping.
10. Jika publish gagal, case tetap terlihat di menu `Tickets` dengan status sync/error agar bisa diretry.

## Mekanisme Integrasi ke IRIS

### Single finding

Alur:

1. Buka detail finding.
2. Klik `Create Ticket`.
3. SATRIA membuat ticket case lokal.
4. SATRIA mengirim alert/case ke IRIS.
5. SATRIA membuat task L1, L2, L3 dan evidence awal.
6. Menu `Tickets` menampilkan status sinkronisasi dan data remote.

### Bulk finding Critical/High

Alur:

1. Buka menu `Reports`.
2. Jalankan bulk send Critical/High ke IRIS.
3. SATRIA hanya mengirim finding yang belum punya ticket.
4. Setiap finding menghasilkan case monitoring yang dapat direfresh dari IRIS.

## Bila Case Tidak Muncul di Monitoring

Cek urutannya:

1. Pastikan finding sudah memiliki ticket lokal.
2. Buka detail ticket dan lihat `Last Sync`.
3. Bila `failed`, lihat `Sync Error`.
4. Perbaiki koneksi atau kredensial IRIS.
5. Jalankan `Publish ke IRIS` atau `Refresh dari IRIS` kembali.

Perilaku sistem saat ini:

- Jika IRIS tidak reachable, halaman SATRIA tidak boleh jatuh.
- Ticket yang gagal sync tetap ditampilkan di `/tickets` agar operator bisa retry.

## Peran Tim SOC

### SOC L1

- Intake alert atau laporan.
- Validasi awal finding.
- Tentukan apakah perlu diangkat menjadi case.
- Lakukan containment awal.
- Eskalasi ke L2 bila valid dan berdampak.

### SOC L2

- Analisis teknis mendalam.
- Korelasi IOC, scope, dan dampak.
- Validasi remediation.
- Koordinasi retest.

### SOC L3

- Lead eradikasi dan recovery.
- Root cause analysis.
- Approval closure.
- Lessons learned dan hardening.

## Batas Operasional yang Harus Dipahami

- SATRIA bukan pengganti IRIS untuk lifecycle case; SATRIA adalah monitor dan penghubung.
- Active scan ZAP dan scan OpenVAS harus mengikuti allowlist dan approval operasional.
- Penghapusan asset yang sudah punya histori akan diarsipkan dari inventory aktif, bukan dihapus total.
- Nomor pada tabel frontend adalah nomor urut tampilan, bukan primary key database.

## Checklist Sebelum Produksi

- `SATRIA_DEMO_MODE=false`
- `IRIS_URL` dan `IRIS_API_KEY` valid
- `SCAN_TARGET_ALLOWLIST` sesuai target operasional
- ZAP container/runner tersedia
- Greenbone/OpenVAS connector tersedia bila `infra_va` dipakai
- Worker dapat mengakses Docker daemon bila scan container image dipakai
