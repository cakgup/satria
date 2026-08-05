# Manual Book Operasional SATRIA

## Navigasi Dokumen Terkait

- [Indeks Dokumentasi SATRIA](README.md)
- [01 - Ringkasan SATRIA](01-RINGKASAN-SATRIA.md)
- [03 - Panduan Operasional SOC](03-PANDUAN-OPERASIONAL-SOC.md)
- [05 - Integrasi Wazuh ke PERISAI](05-INTEGRASI-WAZUH-KE-PERISAI.md)
- [07 - Integrasi AI SOC Wazuh, SATRIA, dan PERISAI](07-INTEGRASI-AI-SOC-WAZUH-SATRIA-PERISAI.md)

---

## 1. Ringkasan

SATRIA adalah aplikasi untuk mengelola aset keamanan, menjalankan pemindaian, membaca hasil temuan, melakukan prioritisasi risiko, dan meneruskan temuan penting ke sistem ticketing atau incident response seperti PERISAI / DFIR-IRIS.

Manual book ini menjelaskan penggunaan SATRIA secara end-to-end untuk kebutuhan operasional harian, mulai dari akses awal, pendaftaran aset, pemindaian, analisis temuan, ticketing, laporan, administrasi, sampai integrasi CI/CD dan ekosistem SOC.

### Tujuan Operasional

- Menyediakan satu tempat untuk registrasi aset yang akan dipindai.
- Menjalankan pemindaian keamanan sesuai jenis target.
- Menormalisasi hasil scanner menjadi findings yang dapat diprioritaskan.
- Menghubungkan temuan penting ke workflow ticketing dan investigasi.
- Menyediakan dashboard ringkas untuk operator, SOC, DevSecOps, dan manajemen.
- Mendukung security gate untuk pipeline build-release.

### Peran Pengguna

| Peran | Kebutuhan Utama |
|---|---|
| Operator SATRIA | Menambah aset, menjalankan scan, memantau status, dan membaca hasil. |
| SOC L1 | Memantau findings, memfilter severity, dan melakukan triase awal. |
| SOC L2/L3 | Menganalisis finding detail, evidence, rekomendasi, dan tindak lanjut. |
| DevSecOps | Menghubungkan pipeline CI/CD ke API SATRIA dan membaca gate decision. |
| Administrator | Mengelola service account, gate policy, allowlist, dan integrasi. |
| Manajemen | Membaca dashboard, tren risiko, dan status tindak lanjut. |

---

## 2. Akses Aplikasi

### URL Operasional

Gunakan alamat berikut untuk operasional internal:

| Layanan | URL / Alamat | Fungsi Operasional |
|---|---|---|
| SATRIA Web Console | `http://10.216.208.249:8090` | Aplikasi utama SATRIA untuk asset, scan, findings, tickets, laporan, admin token, dan gate policy. |
| SATRIA API Docs | `http://10.216.208.249:8090/docs` | Dokumentasi endpoint API SATRIA untuk integrasi pipeline dan otomasi. |
| PERISAI / DFIR-IRIS | `http://10.216.208.249:8092` | Case management, ticketing, investigasi, dan tindak lanjut insiden. |
| Wazuh Manager | `10.216.29.173` | Sumber alert keamanan yang terintegrasi dengan Telegram, email, dan PERISAI / DFIR-IRIS. |

Catatan:

- URL di atas digunakan untuk manual operasional internal.
- Jika alamat berubah, administrator wajib memperbarui tabel ini agar operator menggunakan endpoint yang benar.
- Jangan menggunakan URL lokal pengembangan untuk operasional harian.

### Login

1. Buka `http://10.216.208.249:8090`.
2. Masukkan username dan password yang diberikan administrator.
3. Setelah berhasil login, pengguna diarahkan ke dashboard.
4. Gunakan tombol `Logout` setelah selesai memakai aplikasi.

### Navigasi Sidebar

Menu utama SATRIA berada di sidebar kiri:

| Menu | Fungsi |
|---|---|
| Beranda | Dashboard operasional dan ringkasan risiko. |
| Assets | Pengelolaan aset, target scan, allowlist, dan panduan aset. |
| Pemindaian | Pembuatan, pemantauan, pengulangan, dan penghapusan scan. |
| Findings | Daftar temuan, filter risiko, dan prioritas tindak lanjut. |
| Tickets | Monitoring ticket / case dan koordinasi tindak lanjut. |
| Laporan | Ringkasan kerentanan dan laporan eksekutif. |
| Admin Token | Service account dan token API untuk pipeline/integrasi. |
| Gate Policy | Pengaturan keputusan allowed, need approval, dan blocked. |
| API Docs | Dokumentasi endpoint API otomatis. |

Sidebar dapat disembunyikan atau ditampilkan kembali menggunakan tombol toggle di kiri atas.

---

## 3. Konsep Data SATRIA

### Asset

Asset adalah objek yang menjadi target pemindaian. Asset dapat berupa container image, web application, server IP, repository, atau filesystem.

Field utama:

| Field | Keterangan |
|---|---|
| Nama asset | Nama yang mudah dikenali operator. |
| Jenis target | Tipe target seperti `container_image`, `web_application`, atau `server_ip`. |
| Target | Nilai target scan, misalnya image, URL, IP, repository, atau path. |
| Environment | Lingkungan seperti development, staging, atau production. |
| Criticality | Tingkat kritikalitas asset. |
| Owner | Pemilik sistem atau unit. |
| Technical PIC | PIC teknis untuk koordinasi tindak lanjut. |

### Scan Job

Scan job adalah pekerjaan pemindaian yang dibuat berdasarkan asset dan profile scan.

Status umum:

| Status | Arti |
|---|---|
| queued | Scan sudah dibuat dan menunggu worker. |
| running | Scan sedang diproses. |
| completed | Scan selesai dan hasil tersimpan. |
| failed | Scan gagal diproses. |
| cancelled | Scan dibatalkan. |

### Finding

Finding adalah hasil temuan yang dinormalisasi dari scanner. Finding dapat berasal dari Trivy, Syft, Grype, ZAP, OpenVAS, atau scanner lain yang didukung.

Field umum:

| Field | Keterangan |
|---|---|
| Severity | Critical, High, Medium, Low, atau Informational. |
| Risk | Skor risiko untuk prioritisasi. |
| Scanner | Sumber scanner. |
| Asset | Asset yang terdampak. |
| Title | Judul temuan. |
| CVE/CWE | Identitas kerentanan jika tersedia. |
| Status | Status triase atau remediasi. |

### Ticket

Ticket adalah tindak lanjut formal atas finding atau insiden manual. Ticket dapat berada di SATRIA dan dapat disinkronkan dengan PERISAI / DFIR-IRIS.

---

## 4. Alur Kerja Utama

Alur minimum penggunaan SATRIA:

```text
Login
  -> Tambah asset
  -> Jalankan scan
  -> Pantau status scan
  -> Baca findings
  -> Prioritaskan critical/high
  -> Publish ticket bila diperlukan
  -> Pantau status ticket
  -> Buat laporan
```

Alur ini dapat dilakukan manual melalui UI atau otomatis melalui API pipeline.

---

## 5. Menu Beranda

Menu `Beranda` menampilkan ringkasan kondisi operasional.

Informasi yang biasanya ditampilkan:

- Jumlah asset.
- Jumlah scan.
- Jumlah finding.
- Jumlah ticket.
- Tren severity.
- Pemindaian terbaru.
- Finding prioritas.
- Ringkasan status gate.

Gunakan halaman ini untuk membaca kondisi umum sebelum masuk ke analisis detail.

### Cara Menggunakan

1. Buka menu `Beranda`.
2. Lihat ringkasan jumlah finding dan status scan.
3. Klik area terkait untuk masuk ke halaman detail seperti `Findings` atau `Pemindaian`.
4. Gunakan dashboard sebagai titik awal briefing harian SOC.

---

## 6. Menu Assets

Menu `Assets` digunakan untuk menambahkan, mengubah, mengarsipkan, dan mengelola target pemindaian.

### 6.1 Menambahkan Asset Baru

1. Buka menu `Assets`.
2. Isi form `Tambah asset baru`.
3. Pilih `Jenis target`.
4. Isi `Target` sesuai tipe asset.
5. Isi `Environment`, `Criticality`, `Owner`, dan `Technical PIC`.
6. Klik `Simpan Asset`.

### 6.2 Jenis Target Yang Didukung

| Jenis Target | Contoh Target | Scanner Umum |
|---|---|---|
| `container_image` | `nginx:latest`, `registry.internal/app:tag` | Trivy, Syft, Grype |
| `web_application` | `https://example.go.id` | ZAP |
| `server_ip` | `10.216.208.249` | OpenVAS |
| `web_url` | `https://example.com` | ZAP |
| `source_repository` | `https://git.example/repo.git` | Trivy repo, Syft |
| `filesystem` | `/opt/releases/app` | Trivy fs, Syft |

### 6.3 Panduan Container Image

Untuk asset `container_image`, target adalah nama image dan tag.

Contoh:

```text
nginx:latest
registry.internal/sakti-api:release-2026.07.04
redteam-console-kali-redteam-console:latest
```

Ketentuan:

- Container tidak harus sedang berjalan.
- Image harus tersedia di host SATRIA atau dapat dipull oleh worker SATRIA.
- Jika memakai registry internal, pastikan server SATRIA memiliki akses registry.
- Gunakan tag versi yang jelas, bukan hanya `latest`, untuk release production.

### 6.4 Apakah SATRIA Melakukan Pull Image?

Pada pemindaian `container_image`, SATRIA menjalankan scanner seperti Trivy, Syft, dan Grype terhadap target image.

Perilaku praktis:

- Jika image sudah ada di Docker host SATRIA, scanner menggunakan image lokal.
- Jika image belum ada dan target dapat diakses dari registry, scanner dapat memicu pull image atau resolver registry sesuai tool yang digunakan.
- SATRIA worker memiliki akses Docker host melalui Docker socket.

Untuk efisiensi storage, pastikan tag image tidak menumpuk tanpa kebijakan cleanup.

### 6.5 Arsipkan Asset dan Cleanup Image

Tombol `Arsipkan` pada menu Assets digunakan untuk mengeluarkan asset dari daftar aktif.

Perilaku saat `Arsipkan` diklik:

- Asset diset menjadi tidak aktif.
- Riwayat scan tetap disimpan.
- Findings tetap disimpan.
- Tickets tetap disimpan.
- Report hasil scan tetap disimpan.
- Jika asset berjenis `container_image`, SATRIA mencoba menghapus image lokal dengan `docker image rm <target>`.

Pengaman cleanup image:

- Image tidak dihapus jika masih direferensikan oleh asset aktif lain.
- Image tidak dihapus jika sedang dipakai container berjalan.
- Jika image tidak ada di Docker host, proses arsip tetap berjalan.
- Status cleanup dicatat di audit log.

### 6.6 Edit Asset

1. Buka menu `Assets`.
2. Klik `Edit` pada asset terkait.
3. Perbarui field yang diperlukan.
4. Simpan perubahan.

Gunakan edit untuk memperbaiki nama, environment, criticality, owner, atau target sebelum scan berikutnya.

### 6.7 Allowlist

Allowlist digunakan untuk memastikan target web atau infrastruktur berada dalam cakupan yang diizinkan.

Contoh allowlist:

```text
10.216.208.107
10.216.208.0/24
sipp.internal.go.id
https://sipp.example.go.id
```

Langkah:

1. Buka menu `Assets`.
2. Cari panel allowlist.
3. Isi rule allowlist dan deskripsi.
4. Klik simpan.

Gunakan allowlist untuk mencegah pemindaian target yang tidak disetujui.

---

## 7. Menu Pemindaian

Menu `Pemindaian` digunakan untuk membuat scan job, memantau status, melihat riwayat, mengulang scan, dan menghapus riwayat scan tertentu.

### 7.1 Menjalankan Scan Baru

1. Buka `Pemindaian`.
2. Klik `Jalankan Pemindaian Baru`.
3. Pilih asset.
4. Pilih profile scan.
5. Klik jalankan.

### 7.2 Profile Scan

| Profile | Fungsi |
|---|---|
| `quick_container` | Scan cepat container image, umumnya memakai Trivy. |
| `full_container` | Scan container lebih lengkap dengan Trivy, Syft, dan Grype. |
| `sbom_scan` | Membuat dan menganalisis SBOM container. |
| `web_baseline` | Baseline web scan. |
| `web_full` | Web active scan jika policy mengizinkan. |
| `infrastructure` | Pemindaian infrastruktur / IP. |
| `repo_security` | Pemeriksaan source repository. |

Profile yang muncul dapat disesuaikan berdasarkan konfigurasi sistem.

### 7.3 Memantau Status Scan

Di halaman `Pemindaian`, operator dapat melihat:

- Asset.
- Profile.
- Scanner.
- Status.
- Mode.
- Report path.
- Message.
- Tanggal pembuatan.
- Jumlah findings.

Klik baris scan untuk membuka detail.

### 7.4 Detail Scan

Halaman detail scan menampilkan:

- Metadata scan.
- Status.
- Scanner yang digunakan.
- Path report.
- Message scanner.
- Normalized findings.

Gunakan detail scan untuk melihat apakah scan benar-benar selesai normal dan apakah hasilnya layak ditindaklanjuti.

### 7.5 Ulangi Scan

Gunakan tombol `Ulang` atau `Rerun` untuk menjalankan scan ulang dengan asset dan profile yang sama.

Gunakan rerun bila:

- Image atau target sudah diperbarui.
- Scanner gagal karena timeout sementara.
- Perlu validasi ulang setelah remediation.

### 7.6 Hapus Scan

Menu `Hapus` pada riwayat scan berbeda dengan `Arsipkan` pada asset.

Jika scan dihapus:

- Data scan lokal dapat dihapus.
- Findings turunan dapat dihapus.
- Ticket turunan lokal dapat dihapus.
- Report file dapat dihapus.
- Jika memilih opsi IRIS, case remote dapat ikut dibersihkan bila tersedia.

Gunakan hapus scan hanya jika riwayat tersebut memang tidak diperlukan.

---

## 8. Menu Findings

Menu `Findings` digunakan untuk membaca, memfilter, dan memprioritaskan temuan.

### 8.1 Filter Findings

Filter umum:

- Severity.
- Asset.
- Status.
- Scanner.

Gunakan filter otomatis untuk mempersempit temuan yang perlu ditindaklanjuti.

### 8.2 Prioritas Tindak Lanjut

Urutan prioritas yang disarankan:

1. Critical yang masih open.
2. High yang mengekspos layanan production.
3. Medium pada asset critical.
4. Low yang bersifat hygiene atau hardening.
5. Informational untuk inventaris dan pembelajaran.

### 8.3 Detail Finding

Klik finding untuk membuka detail. Detail finding berisi:

- Identitas finding.
- Severity.
- Risk score.
- Asset terdampak.
- Scanner sumber.
- CVE/CWE bila tersedia.
- Evidence atau raw data.
- Rekomendasi remediation.
- Status tindak lanjut.

### 8.4 Mengubah Status Finding

Status finding dapat diperbarui sesuai proses triase.

Contoh status:

| Status | Kapan Dipakai |
|---|---|
| Open | Temuan baru dan belum ditindaklanjuti. |
| In Progress | Sedang dianalisis atau diremediasi. |
| Risk Accepted | Risiko diterima dengan persetujuan. |
| False Positive | Temuan tidak valid setelah verifikasi. |
| Remediated | Perbaikan sudah dilakukan. |
| Closed | Temuan selesai dan tidak perlu aksi lanjutan. |

### 8.5 Publish Finding ke IRIS

Temuan penting dapat dipublish ke PERISAI / DFIR-IRIS.

Gunakan publish jika:

- Finding critical atau high.
- Finding membutuhkan workflow formal.
- Perlu assignment, task, evidence, dan audit trail.
- Perlu pelaporan remediation lintas tim.

---

## 9. Menu Tickets

Menu `Tickets` digunakan untuk memantau ticket/case yang dibuat dari finding atau dibuat manual.

### 9.1 Monitoring Ticket

Halaman Tickets menampilkan:

- Status ticket.
- Jenis case.
- Status IRIS.
- Jumlah case.
- Case yang perlu ditinjau.
- Distribusi status case.

### 9.2 Membuat Ticket Manual

Ticket manual digunakan untuk insiden yang tidak berasal langsung dari scanner.

Contoh:

- Laporan phishing.
- Indikasi malware.
- Aktivitas mencurigakan dari endpoint.
- Eskalasi manual dari SOC.

Langkah:

1. Buka `Tickets`.
2. Klik tambah/manual case bila tersedia.
3. Pilih playbook.
4. Isi deskripsi dan konteks.
5. Simpan.

### 9.3 Sinkronisasi Dengan IRIS

Jika integrasi IRIS aktif, SATRIA dapat:

- Membuat alert/case di IRIS.
- Menyimpan remote alert ID atau case ID.
- Refresh status ticket dari IRIS.
- Menampilkan status remote untuk monitoring.

Gunakan tombol refresh atau sync bila status lokal perlu diperbarui.

### 9.4 Task, Evidence, dan Activity

Dalam detail ticket, operator dapat menambahkan:

- Activity log.
- Task remediation.
- Evidence.
- Status tindak lanjut.

Gunakan fitur ini untuk menjaga jejak audit.

---

## 10. Menu Laporan

Menu laporan menampilkan ringkasan kerentanan dan performa operasional.

Laporan yang tersedia:

- Ringkasan severity.
- Distribusi scanner.
- Asset terdampak.
- Scan terbaru.
- Temuan prioritas.
- Export CSV.
- Export XLSX.
- Executive Markdown report.

Endpoint laporan:

```text
/reports/findings.csv
/reports/findings.xlsx
/reports/executive.md
```

Gunakan laporan untuk:

- Briefing rutin.
- Bahan rapat remediation.
- Pelaporan status kerentanan.
- Lampiran evidence proses keamanan.

---

## 11. Admin Token

Menu `Admin Token` digunakan untuk membuat dan mengelola service account API.

### 11.1 Kapan Service Account Dibutuhkan

Service account dibutuhkan untuk:

- Integrasi Jenkins.
- Integrasi GitLab CI.
- Pipeline release.
- Sistem eksternal yang membuat scan otomatis.
- Publish ticket otomatis.

### 11.2 Scope Token

| Scope | Fungsi |
|---|---|
| `release:write` | Membuat intake release dari pipeline. |
| `scan:create` | Membuat scan job. |
| `scan:read` | Membaca status dan hasil scan. |
| `ticket:publish` | Publish finding ke ticket/IRIS. |

Gunakan prinsip least privilege. Jangan memberikan scope yang tidak diperlukan.

### 11.3 Membuat Token

1. Buka `Admin Token`.
2. Isi nama service account.
3. Pilih scope.
4. Simpan.
5. Salin token yang muncul.
6. Simpan token di secret manager pipeline.

Token biasanya hanya ditampilkan sekali. Jika hilang, lakukan rotate.

### 11.4 Rotate Token

Lakukan rotate bila:

- Token bocor.
- PIC berubah.
- Pipeline berpindah.
- Kebijakan security mengharuskan rotasi berkala.

---

## 12. Gate Policy

Menu `Gate Policy` digunakan untuk menentukan keputusan release berdasarkan hasil scan.

### 12.1 Jenis Keputusan

| Decision | Arti |
|---|---|
| `allowed` | Release dapat lanjut. |
| `need_approval` | Release perlu persetujuan manual. |
| `blocked` | Release harus dihentikan. |

### 12.2 Contoh Policy

```text
Critical > 0        -> blocked
High >= 1           -> need_approval
Medium >= 15        -> need_approval
Low                 -> allowed
```

### 12.3 Praktik Terbaik

- Critical pada production sebaiknya default `blocked`.
- High pada aplikasi critical minimal `need_approval`.
- Medium dapat diberi threshold agar tidak memblokir release kecil.
- Risk acceptance harus memiliki nomor referensi.
- Perubahan gate policy harus diaudit.

---

## 13. Integrasi CI/CD

SATRIA mendukung alur security gate pada pipeline.

### 13.1 Alur CI/CD

```text
Build image
  -> Push image ke registry
  -> Release intake ke SATRIA
  -> Create scan
  -> Polling status
  -> Ambil result
  -> Evaluasi gate decision
  -> Publish ticket bila diperlukan
```

### 13.2 Endpoint API Utama

| Endpoint | Fungsi |
|---|---|
| `POST /api/v1/releases/intake` | Mendaftarkan release artifact. |
| `POST /api/v1/scans` | Membuat scan job. |
| `GET /api/v1/scans/{scan_id}` | Membaca status scan. |
| `GET /api/v1/scans/{scan_id}/result` | Membaca hasil dan gate decision. |
| `POST /api/v1/scans/{scan_id}/publish-ticket` | Publish finding prioritas ke ticket. |

### 13.3 Payload Release Intake

```json
{
  "asset_code": "SAKTI-API",
  "asset_name": "SAKTI API",
  "release_version": "release-2026.07.04-201-a1b2c3d4",
  "image_ref": "registry.internal/sakti-api:release-2026.07.04-201-a1b2c3d4",
  "image_digest": "registry.internal/sakti-api@sha256:abc123",
  "git_commit": "a1b2c3d4",
  "build_number": "201",
  "environment_target": "production",
  "risk_acceptance_ref": null,
  "gate_override_decision": null
}
```

### 13.4 Payload Create Scan

```json
{
  "asset_id": 1,
  "release_id": 10,
  "image_ref": "registry.internal/sakti-api:release-2026.07.04-201-a1b2c3d4",
  "scan_profile": "quick_container",
  "requested_by": "jenkins",
  "build_number": "201"
}
```

### 13.5 Contoh Curl

```bash
curl -X POST "$SATRIA_URL/api/v1/releases/intake" \
  -H "Authorization: Bearer $SATRIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d @release-intake.json

curl -X POST "$SATRIA_URL/api/v1/scans" \
  -H "Authorization: Bearer $SATRIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d @scan-request.json

curl -H "Authorization: Bearer $SATRIA_TOKEN" \
  "$SATRIA_URL/api/v1/scans/$SCAN_ID"

curl -H "Authorization: Bearer $SATRIA_TOKEN" \
  "$SATRIA_URL/api/v1/scans/$SCAN_ID/result"
```

### 13.6 Interpretasi Gate Decision

Pipeline harus membaca hasil SATRIA dan mengambil keputusan:

```text
allowed       -> lanjut deploy
need_approval -> tahan pipeline dan minta approval
blocked       -> hentikan pipeline
```

Jangan lanjut ke production jika decision `blocked`.

---

## 14. Integrasi PERISAI / DFIR-IRIS

SATRIA dapat meneruskan finding ke PERISAI / DFIR-IRIS.

URL operasional PERISAI / DFIR-IRIS:

```text
http://10.216.208.249:8092
```

### 14.1 Kapan Publish ke IRIS

Publish ke IRIS jika:

- Severity critical atau high.
- Temuan membutuhkan remediation lintas tim.
- Perlu case management formal.
- Perlu evidence dan task terstruktur.

### 14.2 Data Yang Dikirim

Data yang umum dikirim:

- Judul finding.
- Deskripsi.
- Severity.
- Asset terdampak.
- Scanner.
- CVE/CWE.
- Evidence.
- Rekomendasi remediation.
- Raw alert atau raw report bila tersedia.

### 14.3 Monitoring Status IRIS

Setelah publish, SATRIA menyimpan remote ID dan dapat melakukan refresh status.

Gunakan menu `Tickets` untuk memantau:

- Status IRIS.
- Case yang masih open.
- Assignment.
- Progress tindak lanjut.

---

## 15. Integrasi Wazuh, Telegram, dan Email

SATRIA dapat menjadi bagian dari ekosistem SOC bersama Wazuh dan PERISAI.

Alamat operasional Wazuh Manager:

```text
10.216.29.173
```

Ringkasan alur:

```text
Wazuh
  -> Alert level tinggi
  -> Telegram / Email SOC
  -> PERISAI / DFIR-IRIS
  -> SATRIA monitoring dan korelasi
```

Detail integrasi Wazuh tersedia pada:

- [Integrasi Wazuh ke PERISAI](05-INTEGRASI-WAZUH-KE-PERISAI.md)
- [Integrasi AI SOC Wazuh dengan SATRIA dan PERISAI](07-INTEGRASI-AI-SOC-WAZUH-SATRIA-PERISAI.md)

---

## 16. Operasional Harian SOC

### 16.1 Checklist Awal Hari

- [ ] Login ke SATRIA.
- [ ] Buka dashboard Beranda.
- [ ] Cek jumlah scan gagal.
- [ ] Cek findings critical dan high.
- [ ] Cek ticket yang perlu ditinjau.
- [ ] Cek apakah ada asset baru yang perlu discan.
- [ ] Cek status integrasi IRIS bila digunakan.

### 16.2 Checklist Setelah Scan

- [ ] Pastikan status scan `completed`.
- [ ] Buka detail scan.
- [ ] Cek jumlah findings.
- [ ] Prioritaskan critical/high.
- [ ] Tandai false positive bila valid.
- [ ] Publish ticket untuk temuan yang perlu remediation formal.
- [ ] Buat catatan activity bila ada keputusan manual.

### 16.3 Checklist Sebelum Release Production

- [ ] Image memiliki tag immutable.
- [ ] Release intake berhasil.
- [ ] Scan selesai tanpa error.
- [ ] Gate decision bukan `blocked`.
- [ ] Approval tersedia bila decision `need_approval`.
- [ ] Ticket sudah dibuat untuk finding yang wajib ditindaklanjuti.
- [ ] Risk acceptance memiliki referensi resmi bila diperlukan.

---

## 17. Troubleshooting

### 17.1 Scan Container Gagal

Kemungkinan penyebab:

- Image tidak tersedia di Docker host SATRIA.
- Registry internal tidak dapat diakses.
- Credential registry belum tersedia.
- Tag image salah.
- Scanner CLI tidak terpasang.

Langkah cek:

```bash
docker image ls
docker pull registry.internal/app:tag
trivy image registry.internal/app:tag
```

### 17.2 Scan Web Gagal

Kemungkinan penyebab:

- URL tidak dapat diakses dari server SATRIA.
- Target belum masuk allowlist.
- Active scan belum diizinkan.
- TLS certificate tidak dipercaya.

Langkah cek:

```bash
curl -k -I https://target.example
```

### 17.3 Scan Infrastruktur Gagal

Kemungkinan penyebab:

- IP tidak dapat dijangkau.
- OpenVAS belum aktif.
- Credential scanner belum dikonfigurasi.
- Firewall memblokir pemindaian.

### 17.4 Findings Tidak Muncul

Kemungkinan penyebab:

- Scan belum selesai.
- Scanner menghasilkan report kosong.
- Normalisasi gagal.
- Scan berjalan dalam mode demo atau sample.

Langkah cek:

- Buka detail scan.
- Lihat message scanner.
- Cek report path.
- Cek log worker.

### 17.5 Ticket Tidak Terpublish ke IRIS

Kemungkinan penyebab:

- API key IRIS salah.
- Endpoint IRIS tidak dapat diakses.
- Finding tidak memenuhi filter severity.
- IRIS menolak payload.

Langkah cek:

```bash
curl -I http://10.216.208.249:8092
```

### 17.6 Storage Docker Membesar

Kemungkinan penyebab:

- Banyak container image hasil scan.
- Banyak layer image lama.
- Cache scanner menumpuk.

Langkah aman:

- Arsipkan asset container image yang tidak aktif.
- Pastikan image tidak dipakai container berjalan.
- Jalankan cleanup Docker secara terkontrol oleh administrator.

Contoh cek:

```bash
docker system df
docker image ls
```

Hindari `docker system prune -a` tanpa evaluasi karena dapat menghapus image yang masih diperlukan.

---

## 18. Keamanan dan Tata Kelola

### 18.1 Data Sensitif

Untuk manual operasional internal, IP dan port layanan boleh dicantumkan agar operator dapat bekerja dengan tepat. Namun, jangan menyimpan data berikut di repository:

- Password.
- API key.
- Token service account.
- SMTP credential.
- Telegram bot token.

Jika dokumen akan dipublikasikan ke luar organisasi, buat salinan terpisah dan samarkan IP internal, port, hostname, serta detail infrastruktur.

### 18.2 Token API

- Gunakan token berbeda untuk setiap pipeline.
- Scope harus minimum.
- Rotate token berkala.
- Nonaktifkan token yang tidak digunakan.

### 18.3 Registry Credential

- Gunakan credential read-only atau pull-only.
- Jangan gunakan credential personal untuk pipeline production.
- Audit akses registry secara berkala.

### 18.4 Risk Acceptance

Risk acceptance harus memiliki:

- Nomor referensi.
- Alasan bisnis.
- Masa berlaku.
- Approver.
- Rencana remediation.

---

## 19. Backup dan Retensi

### 19.1 Data Yang Perlu Dibackup

- Database SATRIA.
- Volume report.
- File `.env` production.
- Konfigurasi integrasi IRIS.
- Konfigurasi reverse proxy bila ada.

### 19.2 Retensi Report

Report scan berguna untuk audit dan perbandingan hasil. Jangan hapus report jika masih dibutuhkan untuk evidence.

Rekomendasi:

- Report production: 90 sampai 180 hari.
- Report incident critical: ikuti kebijakan retensi organisasi.
- Report demo/smoke test: dapat dibersihkan lebih cepat.

### 19.3 Retensi Docker Image

Image scan tidak harus disimpan permanen di server SATRIA.

Rekomendasi:

- Simpan image release di registry resmi.
- Bersihkan image lokal yang tidak aktif.
- Gunakan tombol `Arsipkan` asset untuk mencoba cleanup image lokal tanpa menghapus history scan.

---

## 20. Contoh Skenario End-to-End

### 20.1 Scan Manual Container Image

1. Operator login ke SATRIA.
2. Buka `Assets`.
3. Tambahkan asset:

```text
Nama       : SAKTI API Dev
Jenis      : container_image
Target     : registry.internal/sakti-api:dev-2026.08.04
Environment: development
Criticality: medium
Owner      : Tim SAKTI
PIC Teknis : DevOps SAKTI
```

4. Pastikan image dapat dipull dari server SATRIA.
5. Klik `Pindai`.
6. Pilih profile `quick_container`.
7. Jalankan scan.
8. Pantau status di `Pemindaian`.
9. Buka findings.
10. Publish critical/high ke IRIS jika perlu.

### 20.2 Security Gate Pipeline

1. Pipeline build image.
2. Pipeline push image ke registry.
3. Pipeline memanggil `POST /api/v1/releases/intake`.
4. Pipeline memanggil `POST /api/v1/scans`.
5. Pipeline polling status.
6. Pipeline membaca result.
7. Pipeline memutuskan:

```text
allowed       -> deploy lanjut
need_approval -> tunggu approval
blocked       -> deploy berhenti
```

8. Pipeline publish ticket bila policy mengharuskan.

### 20.3 Tindak Lanjut Finding Critical

1. SOC membuka menu `Findings`.
2. Filter severity `Critical`.
3. Buka detail finding.
4. Validasi evidence.
5. Jika valid, publish ke IRIS.
6. Tambahkan task remediation.
7. Assign PIC.
8. Setelah perbaikan, rerun scan.
9. Jika finding hilang atau sudah fixed, update status menjadi `Remediated` atau `Closed`.

---

## 21. Glosarium

| Istilah | Arti |
|---|---|
| Asset | Target yang dikelola dan dipindai SATRIA. |
| Scan job | Pekerjaan pemindaian terhadap asset. |
| Finding | Temuan hasil scanner yang sudah dinormalisasi. |
| Ticket | Workflow tindak lanjut temuan atau insiden. |
| IRIS / PERISAI | Sistem case management dan incident response. |
| Gate policy | Kebijakan keputusan release berdasarkan severity. |
| Service account | Akun teknis untuk akses API SATRIA. |
| Release intake | Pendaftaran metadata artefak release dari pipeline. |
| Risk acceptance | Penerimaan risiko secara formal dengan approval. |
| Allowlist | Daftar target yang diizinkan untuk discan. |

---

## 22. Ringkasan Praktik Terbaik

- Daftarkan asset dengan nama yang jelas dan PIC yang valid.
- Gunakan tag image yang immutable untuk production.
- Jalankan `quick_container` untuk gate cepat dan `full_container` untuk validasi lebih lengkap.
- Fokuskan triase awal pada critical dan high.
- Publish ke IRIS hanya untuk temuan yang membutuhkan remediation formal.
- Jangan menghapus riwayat scan jika masih dibutuhkan untuk audit.
- Gunakan `Arsipkan` asset untuk membersihkan image lokal tanpa menghapus history.
- Gunakan service account berbeda untuk setiap pipeline.
- Simpan token dan credential di secret manager.
- Review gate policy secara berkala bersama DevSecOps dan SOC.

Manual book ini dapat digunakan sebagai panduan awal penggunaan SATRIA dan diperbarui mengikuti kebijakan operasional, integrasi, dan tata kelola keamanan organisasi.
