# SOP Hulu-ke-Hilir Per Tim

## Ekosistem Operasional

Dokumen ini menjelaskan alur kerja terpadu antara:

- `PANAH`: platform assessment teknis untuk validasi target, simulasi assessment, dan pengumpulan evidence awal.
- `SATRIA`: platform orkestrasi asset, pemindaian, prioritisasi temuan, pipeline gate, dan pengiriman tiket.
- `PERISAI (DFIR-IRIS)`: platform case management, tasking, evidence handling, koordinasi analisis, dan penutupan insiden.

Dokumen ini dipakai sebagai pedoman operasional bersama bagi tim SOC, pengembang, DevOps, pemilik sistem, dan pimpinan agar seluruh aktivitas keamanan siber berjalan dalam satu alur yang konsisten, terdokumentasi, dan dapat diaudit.

---

## Tujuan

1. Menyatukan alur kerja dari pengujian teknis sampai penutupan insiden.
2. Menegaskan peran setiap tim agar tidak terjadi tumpang tindih kewenangan.
3. Memastikan setiap temuan mempunyai tindak lanjut yang jelas, terukur, dan terdokumentasi.
4. Menjadikan SATRIA sebagai gerbang orkestrasi sebelum temuan dinaikkan menjadi case di PERISAI.
5. Memudahkan pimpinan memantau status risiko, progres remediasi, dan kesiapan operasional.

---

## Ruang Lingkup

SOP ini berlaku untuk:

- pemindaian container image, aplikasi web, server, API endpoint, repository, dan filesystem;
- intake manual dari operator atau hasil assessment teknis dari PANAH;
- pengiriman temuan prioritas dari SATRIA ke PERISAI;
- tindak lanjut oleh SOC L1, SOC L2, SOC L3;
- koordinasi dengan pengembang, DevOps, dan pemilik layanan;
- retest, validasi penutupan, dan pencatatan lesson learned.

---

## Alur Umum Hulu-ke-Hilir

### 1. Intake dan Validasi Target

Sumber intake dapat berasal dari:

- asset yang didaftarkan manual pada SATRIA;
- hasil assessment teknis dari PANAH;
- artefak pipeline CI/CD;
- laporan manual dari pengguna, unit kerja, atau operator;
- monitoring insiden yang langsung dibuat di PERISAI.

Pada tahap ini operator memastikan:

- nama asset jelas dan mudah dikenali;
- jenis target benar;
- owner dan PIC teknis terisi;
- environment sesuai konteks;
- target memang dapat diakses atau tersedia untuk dipindai.

### 2. Assessment Teknis

Assessment dilakukan sesuai konteks:

- `PANAH` untuk assessment teknis, validasi target, simulasi assessment, dan evidence awal;
- `SATRIA` untuk orkestrasi scan operasional menggunakan Trivy, Syft, Grype, ZAP, dan OpenVAS sesuai profil;
- pipeline CI/CD dapat mengirim artefak ke SATRIA untuk diuji sebelum promosi ke tahap berikutnya.

Output tahap ini:

- hasil scan;
- evidence awal;
- metadata tool, waktu, mode, dan status eksekusi;
- daftar findings dan risk score.

### 3. Prioritisasi Temuan

SATRIA digunakan untuk:

- membaca severity dan risk score;
- memfilter temuan berdasarkan asset, scanner, status, dan tingkat risiko;
- membedakan mana yang dapat ditangani lokal dan mana yang perlu dinaikkan menjadi tiket formal;
- menerapkan policy gate `allowed`, `need_approval`, atau `blocked` bila digunakan pada alur pipeline.

### 4. Keputusan Tindak Lanjut

Temuan diputuskan menjadi:

- `monitoring lokal`: untuk item informasional atau risiko rendah yang belum perlu case formal;
- `remediasi internal`: untuk item yang bisa segera ditangani oleh PIC teknis;
- `eskalasi ke PERISAI`: untuk item severity tinggi, berdampak bisnis, berulang, atau membutuhkan koordinasi lintas tim.

### 5. Pembentukan Case di PERISAI

Jika temuan perlu eskalasi:

- SATRIA mengirim tiket ke PERISAI melalui integrasi API;
- case di PERISAI menjadi sumber workflow utama;
- SOC melakukan triase, penugasan, analisis, dan pemantauan lanjutan di PERISAI;
- SATRIA hanya membaca dan memantau status case dari PERISAI.

### 6. Tindak Lanjut oleh Tim SOC

- `SOC L1` melakukan triase awal, validasi, kategorisasi, dan penugasan.
- `SOC L2` melakukan analisis insiden, korelasi evidence, dan rekomendasi teknis.
- `SOC L3` menangani kasus kompleks, containment, eradication, recovery, dan koordinasi strategis.

### 7. Remediasi oleh Tim Teknis

Pengembang, DevOps, atau pemilik sistem:

- menerima detail temuan atau case;
- melakukan perbaikan;
- memberikan bukti perubahan;
- menunggu retest untuk validasi.

### 8. Retest dan Penutupan

Setelah perbaikan selesai:

- SATRIA atau PANAH menjalankan retest;
- hasil retest dibandingkan dengan temuan sebelumnya;
- PERISAI diperbarui hingga status case layak ditutup;
- lesson learned dan tindak lanjut preventif dicatat.

---

## Peran Per Tim

## SOP Tim SOC L1

### Tanggung Jawab Utama

- menerima alert, finding, atau case baru;
- memastikan kelengkapan data awal;
- melakukan triase berdasarkan severity, konteks asset, dan dampak bisnis;
- menentukan apakah item dipantau lokal atau dinaikkan ke case aktif;
- melakukan assignment awal ke analis atau tim lanjutan.

### Langkah Operasional

1. Buka SATRIA untuk melihat temuan baru, status scan, dan konteks asset.
2. Validasi apakah target, severity, scanner, dan evidence awal sudah masuk akal.
3. Tentukan apakah temuan:
   - cukup dicatat;
   - perlu koordinasi cepat ke PIC teknis;
   - perlu dikirim menjadi case di PERISAI.
4. Jika sudah menjadi case di PERISAI, pastikan:
   - judul case jelas;
   - severity sesuai;
   - owner awal terisi;
   - task awal dibuat;
   - evidence awal tersedia.
5. Ubah status case di PERISAI sesuai hasil triase.
6. Berikan eskalasi ke SOC L2 jika:
   - ada indikasi eksploitasi aktif;
   - dampak belum jelas;
   - ada temuan berulang pada asset penting;
   - kasus menyangkut akun, data sensitif, atau layanan publik.

### Output L1

- case tervalidasi;
- prioritas awal;
- assignment awal;
- catatan triase;
- rekomendasi eskalasi atau tindak lanjut cepat.

---

## SOP Tim SOC L2

### Tanggung Jawab Utama

- melakukan analisis teknis lanjutan;
- mengkorelasikan evidence;
- menilai akar masalah dan jalur dampak;
- menyusun rekomendasi perbaikan dan containment;
- berkoordinasi dengan pengembang atau DevOps.

### Langkah Operasional

1. Tinjau case di PERISAI beserta evidence dari SATRIA atau PANAH.
2. Pastikan temuan benar, bukan false positive.
3. Lakukan korelasi:
   - asset terdampak;
   - versi komponen;
   - log aplikasi atau sistem;
   - exposure jaringan;
   - histori temuan serupa.
4. Tambahkan task analisis dan evidence tambahan di PERISAI.
5. Rumuskan:
   - akar masalah;
   - dampak aktual dan potensial;
   - prioritas remediasi;
   - langkah teknis yang harus dilakukan tim pengembang atau infrastruktur.
6. Jika ditemukan risiko tinggi, informasikan ke L3 atau pimpinan teknis sesuai jalur eskalasi.
7. Setelah ada perbaikan, minta retest melalui SATRIA atau assessment pendukung.

### Output L2

- analisis teknis rinci;
- evidence tambahan;
- rekomendasi remediasi;
- penilaian dampak;
- keputusan apakah kasus dapat dilanjutkan ke recovery atau harus dieskalasikan ke L3.

---

## SOP Tim SOC L3

### Tanggung Jawab Utama

- menangani kasus kompleks dan berdampak besar;
- memimpin containment, eradication, dan recovery;
- menentukan strategi respons insiden;
- melakukan koordinasi lintas unit;
- memberi keputusan akhir teknis sebelum penutupan.

### Langkah Operasional

1. Ambil alih atau review case dari L2 bila ada:
   - indikasi compromise;
   - potensi lateral movement;
   - dampak layanan kritikal;
   - eskalasi pimpinan;
   - kebutuhan keputusan lintas sistem.
2. Tentukan langkah containment:
   - isolasi host;
   - pembatasan akses;
   - blokir IOC;
   - rollback artefak release;
   - penghentian promosi pipeline.
3. Tentukan langkah eradication:
   - patch atau upgrade;
   - rotasi kredensial;
   - perbaikan konfigurasi;
   - pembersihan artefak berbahaya;
   - rebuild image atau environment.
4. Pimpin recovery:
   - validasi layanan pulih;
   - pastikan risiko residu dapat diterima;
   - tentukan retest atau hardening lanjutan.
5. Dokumentasikan keputusan teknis strategis pada case PERISAI.

### Output L3

- keputusan containment;
- keputusan eradication;
- validasi recovery;
- rekomendasi hardening;
- persetujuan penutupan teknis atau pemantauan lanjutan.

---

## SOP Tim Pengembang

### Tanggung Jawab Utama

- memperbaiki kelemahan pada aplikasi atau komponen;
- menindaklanjuti temuan dari SATRIA dan case dari PERISAI;
- memberi bukti implementasi perbaikan;
- mendukung retest.

### Langkah Operasional

1. Terima detail ticket atau case dari SOC.
2. Identifikasi:
   - komponen terdampak;
   - versi rentan;
   - lokasi source code atau image;
   - potensi dampak ke release plan.
3. Lakukan perbaikan:
   - upgrade dependency;
   - patch source code;
   - perbaikan header atau konfigurasi keamanan;
   - hardening pipeline;
   - perubahan Dockerfile atau base image.
4. Kirim bukti:
   - commit atau release note;
   - hash image baru;
   - hasil build;
   - artefak yang siap diuji ulang.
5. Koordinasikan retest dengan SOC melalui SATRIA.

### Output Tim Pengembang

- perbaikan teknis;
- bukti perubahan;
- artefak baru untuk diuji;
- umpan balik terhadap rekomendasi SOC bila ada kendala implementasi.

---

## SOP Tim DevOps / Infrastruktur

### Tanggung Jawab Utama

- memastikan artefak, host, registry, dan pipeline dapat diuji dengan benar;
- menerapkan hardening sistem;
- membantu rollout dan rollback yang aman;
- menjaga integrasi SATRIA ke pipeline dan lingkungan target.

### Langkah Operasional

1. Pastikan registry, image, host, atau URL tersedia untuk diuji.
2. Kelola allowlist dan gate policy jika active scan memerlukan persetujuan.
3. Integrasikan pipeline ke SATRIA menggunakan service account dan API key yang sesuai.
4. Laksanakan:
   - pull image ke host SATRIA bila diperlukan;
   - deploy ke staging untuk uji aktif;
   - rollback artefak jika gate gagal;
   - promosi ke production hanya bila status memenuhi kebijakan.
5. Dokumentasikan perubahan lingkungan dan hasil rollout.

### Output Tim DevOps

- readiness environment;
- integrasi pipeline;
- evidence deployment atau rollback;
- status promosi release.

---

## SOP Pemilik Sistem / Unit Bisnis

### Tanggung Jawab Utama

- menyediakan konteks bisnis;
- menentukan prioritas layanan;
- menyetujui risk acceptance bila diperlukan;
- memastikan tindak lanjut tidak mengganggu layanan tanpa koordinasi.

### Langkah Operasional

1. Memberi informasi owner, PIC, dan klasifikasi layanan.
2. Menyepakati prioritas pemulihan atau jendela perubahan.
3. Menyetujui mitigasi atau compensating control bila remediasi penuh belum bisa dilakukan.
4. Menjadi pihak yang diinformasikan pada kasus penting atau berisiko tinggi.

### Output

- konteks bisnis;
- keputusan prioritas layanan;
- persetujuan mitigasi atau acceptance;
- dukungan koordinasi lintas unit.

---

## SOP Admin Platform

### Tanggung Jawab Utama

- menjaga layanan PANAH, SATRIA, dan PERISAI tetap aktif;
- mengelola user, token, service account, policy, dan integrasi;
- menjaga integritas data dan keterlacakan.

### Langkah Operasional

1. Pastikan seluruh service backend berjalan.
2. Kelola:
   - API key;
   - service account pipeline;
   - gate policy;
   - allowlist active scan;
   - integrasi IRIS.
3. Menangani kegagalan sinkronisasi atau error publish ke PERISAI.
4. Menyediakan dukungan teknis saat onboarding tim baru.

### Output

- platform aktif;
- integrasi sehat;
- token dan policy terkelola;
- log perubahan administrasi.

---

## SOP Pimpinan / Top Management

### Tanggung Jawab Utama

- memantau posisi risiko secara ringkas;
- memastikan ada tindak lanjut terhadap kasus prioritas;
- mengambil keputusan bila ada eskalasi lintas unit atau dampak tinggi.

### Fokus Pemantauan

- jumlah asset aktif;
- jumlah scan dan temuan prioritas;
- status ticket di PERISAI;
- backlog open, assigned, in progress, dan closed;
- tren perbaikan dan risiko residu;
- efektivitas gate pada pipeline.

### Output Pimpinan

- persetujuan eskalasi;
- keputusan prioritas organisasi;
- dukungan sumber daya;
- arahan perbaikan proses.

---

## Kriteria Eskalasi dari SATRIA ke PERISAI

Temuan dikirim ke PERISAI bila memenuhi salah satu kondisi berikut:

- severity `critical` atau `high`;
- berdampak pada layanan publik atau sistem kritikal;
- ada indikasi eksploitasi atau aktivitas mencurigakan;
- membutuhkan koordinasi lintas unit;
- membutuhkan tasking formal, evidence lanjutan, dan jejak audit;
- berulang pada asset yang sama;
- terkait gate pipeline yang memblokir promosi release penting.

---

## Kriteria Penutupan

Case dapat ditutup bila:

- akar masalah telah ditangani;
- evidence perbaikan tersedia;
- retest menunjukkan hasil sesuai harapan;
- risiko residu dinilai dapat diterima;
- owner layanan mengetahui status akhir;
- seluruh task dan evidence di PERISAI telah lengkap.

---

## Checklist Minimum Per Case

- identitas asset;
- jenis target;
- severity dan risk score;
- deskripsi temuan;
- dampak bisnis;
- rekomendasi teknis;
- owner dan PIC;
- evidence awal;
- keputusan triase;
- status tindak lanjut;
- bukti remediasi;
- hasil retest;
- catatan penutupan.

---

## Ringkasan Tanggung Jawab Per Fase

### Fase Intake

- L1: validasi awal
- Admin platform: jaga integrasi
- Owner sistem: beri konteks

### Fase Assessment

- PANAH / SATRIA operator: jalankan pengujian
- DevOps: siapkan target
- Pengembang: siapkan artefak atau konteks aplikasi

### Fase Prioritisasi

- L1: triase
- L2: validasi teknis
- Pimpinan: lihat ringkasan risiko bila dibutuhkan

### Fase Respons

- L2: analisis
- L3: keputusan strategis
- Pengembang/DevOps: remediasi

### Fase Penutupan

- L2/L3: validasi teknis
- Owner sistem: konfirmasi operasional
- Pimpinan: menerima ringkasan akhir bila kasus signifikan

---

## Prinsip Operasional

1. Satu sumber kerja untuk assessment teknis, satu sumber kerja untuk case formal.
2. SATRIA dipakai untuk orkestrasi scan, pembacaan temuan, dan pengiriman tiket.
3. PERISAI dipakai sebagai workflow case utama setelah tiket formal terbentuk.
4. PANAH dipakai untuk assessment teknis yang membutuhkan simulasi dan evidence awal.
5. Seluruh keputusan penting harus tercatat, bukan hanya disampaikan lisan.

