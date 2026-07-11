# Walkthrough IRIS dan Alur SATRIA ke IRIS Untuk Top Management

Dokumen ini disusun untuk membantu pimpinan memahami dua jalur masuk kerja insiden ke DFIR-IRIS:

- tiket atau case yang dibuat langsung di IRIS
- tiket yang berasal dari hasil pemindaian SATRIA lalu dipublish ke IRIS

Dengan demikian, IRIS dapat dipahami bukan hanya sebagai aplikasi ticketing, melainkan sebagai pusat dokumentasi, koordinasi, dan pengendalian tindak lanjut insiden dari hulu ke hilir.

## Tujuan Walkthrough

- Menjelaskan posisi IRIS dalam operasional SOC.
- Menunjukkan hubungan kerja SATRIA dan IRIS.
- Memperlihatkan bagaimana data teknis dari SATRIA mengalir ke IRIS.
- Menjelaskan pembagian peran L1, L2, L3, pengembang, dan stakeholder.
- Memberikan skenario demo yang mudah dipresentasikan kepada top management.

## Aplikasi dan Perannya

### SATRIA

SATRIA adalah platform operasional untuk:

- pendaftaran asset
- orkestrasi pemindaian
- normalisasi temuan
- prioritisasi risiko
- pemantauan hasil scanner
- pengiriman finding prioritas menjadi tiket atau case ke IRIS

### IRIS

DFIR-IRIS adalah platform manajemen kasus insiden untuk:

- intake dan tracking case
- pembagian task antar-analis
- pencatatan timeline kegiatan
- pencatatan IOC
- pencatatan asset terdampak
- penyimpanan evidence
- pencatatan summary dan closure
- dokumentasi koordinasi dengan pengembang dan stakeholder

## Relasi SATRIA dan IRIS

Secara sederhana:

1. SATRIA menghasilkan temuan dari scanner.
2. Temuan yang relevan diprioritaskan oleh operator.
3. Operator mengirim finding ke IRIS.
4. IRIS menjadi sistem utama untuk pengelolaan kasus, koordinasi penanganan, dan dokumentasi lengkap.

Artinya:

- SATRIA berfungsi sebagai mesin operasional scanning dan prioritisasi.
- IRIS berfungsi sebagai sistem ticketing dan case management lanjutan.

## Akses Demo

- SATRIA: `http://<SATRIA_HOST>:<SATRIA_PORT>`
- IRIS: `https://<PERISAI_HOST>:<PERISAI_PORT>`

Catatan keamanan:

- alamat host pada dokumen ini menggunakan placeholder;
- gunakan URL operasional aktual dari inventaris infrastruktur atau secret portal internal.
- Customer demo IRIS: `DJPb - Simulasi IRIS Top Management`

Persona demo yang tampak di IRIS:

- `SOCL1`
- `SOCL2`
- `SOCL3`
- stakeholder / owner system
- pengembang / tim aplikasi

## Dua Jalur Masuk Case ke IRIS

## 1. Jalur Manual Langsung di IRIS

Jalur ini digunakan bila insiden berasal dari:

- laporan pengguna
- laporan unit kerja
- laporan helpdesk
- hasil monitoring di luar SATRIA
- eskalasi manajerial atau audit

### Alur Hulu ke Hilir

1. Laporan atau indikasi insiden diterima oleh SOC.
2. SOC L1 membuat case secara manual di IRIS.
3. L1 mengisi identitas awal case, severity, owner awal, deskripsi singkat, dan aset terdampak.
4. L1 membuat task awal dan mencatat kronologi awal.
5. SOC L2 mengambil alih analisis teknis, menambah IOC, asset, note, dan evidence.
6. SOC L3 menjalankan containment, eradikasi, hardening, dan recovery.
7. Jika akar masalah ada pada aplikasi atau sistem, pengembang atau owner system dilibatkan.
8. Stakeholder menerima ringkasan status dan keputusan tindak lanjut.
9. Setelah verifikasi selesai, case ditutup dengan outcome yang sesuai.

### Contoh Skenario Manual yang Cocok

- phishing email ke salah satu KPPN
- malware pada laptop pegawai
- laporan akses tidak sah dari unit internal
- insiden operasional yang belum berasal dari hasil scanner

## 2. Jalur SATRIA ke IRIS

Jalur ini digunakan bila insiden atau finding berasal dari hasil pemindaian SATRIA.

### Sumber Temuan SATRIA

SATRIA dapat menghasilkan temuan dari:

- `Syft`: inventaris komponen software
- `Grype`: deteksi CVE pada komponen
- `Trivy`: scanner serbaguna untuk container, repo, IaC, dan secret
- `ZAP`: scanner keamanan aplikasi web
- `OpenVAS`: scanner keamanan server dan jaringan

### Menu di SATRIA yang Terlibat

Urutan menu SATRIA yang relevan adalah:

1. `Assets`
2. `Scans`
3. `Findings`
4. `Tickets`
5. `Reports`

### Alur SATRIA ke IRIS dari Hulu ke Hilir

#### Tahap A. Asset didaftarkan di SATRIA

Di menu `Assets`, operator mendaftarkan target yang akan diuji, misalnya:

- container image
- web application
- server atau IP
- source repository
- filesystem
- API endpoint

Field yang biasanya diisi:

- nama asset
- jenis target
- target
- environment
- criticality
- owner
- technical PIC

#### Tahap B. Pemindaian dijalankan di SATRIA

Di menu `Scans` atau melalui tombol `Jalankan Scan Baru`, operator memilih:

- asset
- profile scan
- scanner yang sesuai

Contoh:

- container image: `quick_container`, `sbom_scan`, `full_container`
- web application: `web_baseline`, `web_full`
- server atau IP: `infra_va`

#### Tahap C. Hasil dipantau di SATRIA

Di menu `Scans`, operator memantau:

- status job
- scanner yang dipakai
- jumlah finding
- report scanner
- mode real atau simulated

#### Tahap D. Finding diprioritaskan di SATRIA

Di menu `Findings`, operator melakukan:

- filter berdasarkan severity
- filter berdasarkan asset
- filter berdasarkan status
- filter berdasarkan scanner
- review detail finding
- perubahan status lokal seperti `Open`, `Assigned`, atau lainnya

Di tahap ini, operator menentukan apakah finding cukup dimonitor di SATRIA atau harus dinaikkan ke IRIS.

#### Tahap E. Finding dikirim ke IRIS

Setelah finding dinilai penting, operator membuat tiket dari SATRIA.

Titik input yang umum:

- dari detail finding melalui tombol kirim tiket atau publish ke IRIS
- dari menu `Reports` untuk bulk action `Critical/High`
- dari menu `Tickets` untuk memantau hasil sinkronisasi

Saat operator mengirim finding ke IRIS, SATRIA melakukan beberapa hal:

1. membuat mirror ticket lokal di SATRIA
2. membangun payload case untuk IRIS
3. mengirim metadata finding ke IRIS
4. menyimpan referensi `remote case`
5. menyinkronkan status sinkronisasi dan error bila ada

### Data Yang Dibawa dari SATRIA ke IRIS

Secara operasional, finding yang dipublish dari SATRIA ke IRIS dapat membawa:

- judul kasus
- severity
- deskripsi temuan
- asset terkait
- scanner sumber
- CVE atau CWE bila ada
- rekomendasi awal
- evidence atau artefak awal
- task awal
- metadata sinkronisasi

Dengan kata lain, IRIS tidak menerima tiket kosong. IRIS menerima konteks awal yang sudah diperkaya oleh SATRIA.

## Apa yang Terjadi Setelah Case Masuk ke IRIS

Setelah finding dari SATRIA berhasil dipublish, IRIS menjadi pusat tindak lanjut.

### Tahap 1. L1 melakukan validasi operasional

SOC L1:

- memeriksa apakah case sesuai konteks bisnis
- memastikan asset dan owner sudah benar
- menilai apakah severity awal tetap atau perlu ditinjau
- menambahkan timeline awal bila perlu

### Tahap 2. L2 melakukan analisis teknis

SOC L2:

- menelaah detail finding dari SATRIA
- memperkaya IOC
- menghubungkan bukti tambahan
- memperjelas dampak dan ruang lingkup
- mengusulkan langkah containment

### Tahap 3. L3 menangani response lanjutan

SOC L3:

- memimpin containment
- menentukan eradikasi
- memastikan recovery
- mengarahkan hardening
- menilai root cause

### Tahap 4. Handoff ke pengembang atau owner system

Bila masalah berasal dari:

- kerentanan aplikasi
- konfigurasi server
- secret yang bocor
- kesalahan kontrol autentikasi
- kelemahan pipeline atau image

maka IRIS dipakai untuk mencatat koordinasi dengan:

- pengembang
- DevOps
- owner layanan
- pengelola infrastruktur

### Tahap 5. Pelaporan ke stakeholder

IRIS juga dipakai untuk:

- mencatat pembaruan status
- menyiapkan executive summary
- menyimpan lesson learned
- mendokumentasikan keputusan penutupan

## Cara Menjelaskan Skenario SATRIA ke IRIS kepada Pimpinan

Penjelasan yang paling mudah adalah:

1. SATRIA mencari dan menyusun temuan teknis.
2. Temuan yang paling penting dipilih operator.
3. Temuan tersebut dikirim ke IRIS.
4. Di IRIS, temuan berubah menjadi case yang dapat ditindaklanjuti lintas peran.
5. Semua langkah lanjutan, bukti, dan keputusan terdokumentasi di IRIS sampai penutupan.

## Skenario Demo Komprehensif Yang Disarankan

## Skenario A. Input Manual Langsung di IRIS

### Judul Contoh

`Insiden malware pada laptop pegawai KPPN`

### Narasi Hulu ke Hilir

1. Pegawai melapor bahwa laptop melambat dan muncul alert antivirus.
2. SOC L1 membuat case manual di IRIS.
3. L1 mengisi severity, deskripsi, asset laptop, user terkait, dan kronologi awal.
4. L2 menganalisis hash file, scheduled task, startup item, dan koneksi outbound.
5. L3 memutuskan isolasi, eradikasi, reset kredensial, dan pemulihan endpoint.
6. Evidence, timeline, IOC, dan rekomendasi dicatat di IRIS.
7. Setelah endpoint dinyatakan bersih, case ditutup dan lesson learned didokumentasikan.

### Nilai Yang Diperlihatkan

- IRIS mampu menangani insiden yang tidak berasal dari scanner.
- IRIS cocok untuk kasus helpdesk, user report, dan investigasi manual.

## Skenario B. Input dari SATRIA ke IRIS

### Judul Contoh

`Finding critical dari scan container image SATRIA`

### Narasi Hulu ke Hilir

1. Tim teknis mendaftarkan asset container image di menu `Assets` SATRIA.
2. Operator menjalankan scan container melalui menu `Scans`.
3. SATRIA menghasilkan finding, misalnya CVE kritikal dari `Trivy`, `Syft`, dan `Grype`.
4. Operator membuka menu `Findings` dan memfilter severity `Critical`.
5. Operator memilih finding yang relevan lalu menekan tombol kirim ke IRIS.
6. SATRIA membuat ticket lokal dan mempublish finding ke IRIS.
7. Di menu `Tickets` SATRIA, operator melihat apakah publish berhasil dan memperoleh nomor remote case.
8. Di IRIS, case muncul sebagai kasus baru dengan konteks teknis awal dari SATRIA.
9. SOC L1 memverifikasi konteks bisnis dan ownership.
10. SOC L2 memeriksa komponen terdampak, paket, versi aman, dan scope image lain yang serupa.
11. SOC L3 berkoordinasi dengan pengembang atau DevOps untuk rebuild image, hardening, atau patch dependency.
12. Setelah image baru lolos retest, case di IRIS diperbarui dan akhirnya ditutup.

### Nilai Yang Diperlihatkan

- scanner teknis tidak berhenti di laporan mentah
- finding penting dapat diteruskan menjadi case terstruktur
- IRIS menampung tindak lanjut lintas tim sampai selesai

## Pemetaan Menu SATRIA ke Fungsi IRIS

### Menu `Assets` di SATRIA

Fungsi manajerial:

- menentukan objek yang diawasi
- memberi konteks owner dan PIC

Dampak ke IRIS:

- asset di IRIS menjadi lebih mudah dimengerti karena asal targetnya jelas

### Menu `Scans` di SATRIA

Fungsi manajerial:

- menunjukkan aktivitas pemindaian yang sedang dan sudah berjalan

Dampak ke IRIS:

- memberi jejak sumber awal temuan

### Menu `Findings` di SATRIA

Fungsi manajerial:

- tempat operator memilih temuan yang penting untuk dinaikkan

Dampak ke IRIS:

- menjadi pintu masuk temuan teknis ke case management

### Menu `Tickets` di SATRIA

Fungsi manajerial:

- memantau apakah data dari SATRIA berhasil tersinkron ke IRIS

Dampak ke IRIS:

- menjadi jembatan monitoring antara sumber finding dan case remote

### Menu `Reports` di SATRIA

Fungsi manajerial:

- menyiapkan bulk action untuk finding prioritas

Dampak ke IRIS:

- memungkinkan pengiriman banyak finding kritikal atau high menjadi antrian case

## Data Dummy Yang Sudah Diisi di IRIS

Saat dokumen ini dibuat, IRIS sudah berisi:

- 20 case dummy utama dengan kode `INC-DUMMY-001` sampai `INC-DUMMY-020`
- campuran case `Open` dan `Closed`
- variasi skenario seperti phishing, malware, brute force, SQL injection, data exfiltration, policy violation, webshell, dan credential leak

Setiap case diisi agar memperlihatkan elemen berikut:

- case metadata
- owner
- status
- tasks
- notes
- IOC
- assets
- evidence
- summary

## Case Unggulan Yang Disarankan Saat Presentasi

- `INC-DUMMY-001`: brute force attempt
- `INC-DUMMY-002`: phishing email
- `INC-DUMMY-003`: malware endpoint
- `INC-DUMMY-010`: data download anomali
- `INC-DUMMY-020`: kebocoran kredensial pada repository dan handoff ke pengembang

## Pemetaan Peran

### SOC L1

- menerima alert atau laporan
- membuat intake
- memverifikasi temuan awal
- memastikan ownership
- melakukan eskalasi awal

### SOC L2

- melakukan analisis teknis
- enrichment IOC
- validasi risiko
- memperluas scoping

### SOC L3

- containment
- eradikasi
- hardening
- recovery
- koordinasi teknis lanjutan

### Pengembang / DevOps / Owner System

- menerima handoff bila akar masalah ada pada kode, konfigurasi, image, pipeline, atau dependency
- melaksanakan perubahan
- mendukung retest dan closure

### Stakeholder / Pimpinan

- menerima ringkasan dampak
- melihat status tindak lanjut
- memahami kebutuhan keputusan operasional atau tata kelola

## Urutan Presentasi 10 Menit Yang Disarankan

1. Mulai dari penjelasan peran SATRIA dan IRIS.
2. Jelaskan ada dua jalur masuk: manual dan dari SATRIA.
3. Tunjukkan daftar case di IRIS.
4. Buka satu case manual untuk menunjukkan alur non-scanner.
5. Buka satu case hasil SATRIA untuk menunjukkan integrasi scanning ke case management.
6. Tunjukkan task, IOC, assets, evidence, dan summary.
7. Tutup dengan penjelasan bahwa IRIS adalah sistem kerja lanjutan setelah deteksi atau finding terjadi.

## Pesan Utama Untuk Pimpinan

- SATRIA dan IRIS membentuk satu alur operasional yang saling terhubung.
- SATRIA fokus pada deteksi, prioritisasi, dan pemilihan finding penting.
- IRIS fokus pada penanganan, koordinasi, dokumentasi, dan penutupan kasus.
- Keduanya bersama-sama membentuk rantai kerja yang lebih tertib, terukur, dan dapat diaudit.
