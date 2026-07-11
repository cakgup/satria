# SATRIA + DFIR-IRIS Demo SOP

## Dokumen Pendamping

- Walkthrough top management IRIS: [IRIS-TOP-MANAGEMENT-WALKTHROUGH.md](C:/Users/gufroni/Documents/GitHub/satria/docs/IRIS-TOP-MANAGEMENT-WALKTHROUGH.md)

## Akses

- SATRIA: `http://<SATRIA_LOCAL_HOST>:<SATRIA_PORT>`
- DFIR-IRIS: `https://<PERISAI_LOCAL_HOST>:<PERISAI_PORT>`
- IRIS admin:
  - username: `<iris-admin-username>`
  - password: `<iris-admin-password>`

## User Demo SOC

- L1: `<soc-l1-username>` / `<soc-l1-password>`
- L2: `<soc-l2-username>` / `<soc-l2-password>`
- L3: `<soc-l3-username>` / `<soc-l3-password>`

Ketiga user sudah dibuat di DFIR-IRIS dan dimasukkan ke grup `Analysts`.

Catatan keamanan:

- semua identitas user demo, password, host, dan port pada dokumen ini sudah disamarkan;
- simpan nilai aktual di password vault atau credential manager internal.

## Case Demo Yang Sudah Tersinkron

Selain case manual awal, environment IRIS telah diisi 20 case dummy terstruktur dengan kode:

- `INC-DUMMY-001` sampai `INC-DUMMY-020`

Case-case tersebut dibuat untuk menggambarkan alur lengkap:

- intake dan triase awal
- eskalasi SOC L1 ke L2 dan L3
- koordinasi ke pengembang atau pemilik layanan
- evidence, IOC, asset, notes, task, dan summary
- closure pada sebagian case agar dashboard terlihat realistis

## Dua Jalur Input ke IRIS

### 1. Manual langsung di IRIS

Dipakai untuk insiden yang berasal dari:

- laporan user
- laporan unit kerja
- monitoring non-SATRIA
- eskalasi manual

Contoh:

- phishing email
- malware endpoint
- akses tidak sah yang dilaporkan helpdesk

### 2. Dari SATRIA ke IRIS

Dipakai untuk finding hasil scanning SATRIA yang perlu dinaikkan menjadi case.

Alur ringkas:

1. `Assets`: daftar target
2. `Scans`: jalankan profile scan
3. `Findings`: review dan pilih finding prioritas
4. kirim finding ke IRIS
5. `Tickets`: pantau sinkronisasi dan remote case

Di IRIS, case hasil SATRIA lalu diteruskan oleh SOC L1, L2, L3 sampai ke pengembang atau stakeholder bila diperlukan.

## Skenario Demo SATRIA ke IRIS

### Container image ke IRIS

1. Daftarkan image di menu `Assets`.
2. Jalankan scan container di menu `Scans`.
3. Buka menu `Findings`.
4. Filter severity `Critical` atau `High`.
5. Buka detail finding lalu kirim ke IRIS.
6. Cek menu `Tickets` untuk memastikan remote case berhasil dibuat.
7. Lanjutkan investigasi dan task lanjutan di IRIS.

### Web application ke IRIS

1. Daftarkan URL aplikasi di menu `Assets`.
2. Jalankan `web_baseline` atau `web_full`.
3. Review temuan ZAP di menu `Findings`.
4. Kirim finding yang valid ke IRIS.
5. Di IRIS, tim SOC dan pengembang menindaklanjuti hasilnya sampai retest selesai.

## SOP Operasional

### L1

1. Terima alert atau laporan user.
2. Validasi apakah insiden relevan dan buat/update ticket di SATRIA.
3. Isolasi awal aset jika perlu.
4. Tambahkan activity awal dan evidence awal.
5. Eskalasi ke L2 jika butuh analisis lebih lanjut.

### L2

1. Analisis IOC, artefak, header email, domain, hash, process, persistence, dan scope.
2. Update task L2 dan activity timeline.
3. Tentukan rekomendasi containment dan eradikasi.
4. Eskalasi ke L3 bila perlu perubahan kontrol, hardening, atau forensik lanjutan.

### L3

1. Putuskan eradikasi, hardening, recovery, dan koordinasi lintas sistem.
2. Validasi root cause dan pastikan IOC diblok.
3. Pastikan evidence final, timeline final, dan resolution summary lengkap.
4. Tutup case setelah retest atau verifikasi pemulihan selesai.

## Alur Demo Manual

### Malware laptop pegawai KPPN

1. L1 menerima laporan laptop lambat dan antivirus alert.
2. L1 membuat ticket manual `malware-endpoint`, isolasi endpoint, dan simpan evidence awal.
3. L2 memeriksa hash file, scheduled task, startup item, dan koneksi outbound.
4. L3 menentukan eradikasi, reset kredensial, blok IOC, dan recovery endpoint.
5. Case ditutup setelah endpoint bersih dan user menerima edukasi singkat.

### Phishing pada salah satu KPPN

1. L1 menerima laporan email mencurigakan.
2. L1 membuat ticket manual `phishing-email`, kumpulkan header, URL, dan daftar user terdampak.
3. L2 menganalisis domain, URL, artefak email, dan indikasi credential submission.
4. L3 koordinasi blok domain/sender, purge email, dan reset akun bila compromise terkonfirmasi.
5. Case ditutup setelah hunting selesai dan exposure sudah ditangani.
