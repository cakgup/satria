# Ringkasan Top Management 1 Halaman

## PANAH, SATRIA, dan PERISAI dalam Satu Alur Kerja

Ekosistem ini dibangun agar pengujian teknis, orkestrasi pemindaian, dan penanganan insiden tidak berjalan terpisah. Tiga platform diposisikan sebagai satu rantai kerja terpadu:

- `PANAH`: melakukan assessment teknis dan pengumpulan evidence awal.
- `SATRIA`: mengelola asset, scan, prioritas temuan, policy gate, dan pengiriman tiket.
- `PERISAI (DFIR-IRIS)`: mengelola case, task, evidence, analisis, eskalasi, dan penutupan insiden.

---

## Nilai Utama Bagi Pimpinan

### 1. Visibilitas Risiko yang Lebih Jelas

Pimpinan dapat melihat:

- asset yang aktif dipantau;
- jumlah temuan prioritas;
- status tiket dan progres tindak lanjut;
- backlog open, assigned, in progress, dan closed.

### 2. Satu Alur Kerja yang Terdokumentasi

Assessment teknis tidak berhenti pada hasil scan. Temuan yang relevan dapat diteruskan menjadi ticket formal, dikelola sampai selesai, lalu diverifikasi kembali.

### 3. Koordinasi Lintas Tim Lebih Tertib

Setiap peran memiliki ruang kerja yang jelas:

- tim teknis menguji;
- SOC memvalidasi dan mengeskalasi;
- pengembang memperbaiki;
- pimpinan memantau keputusan dan progres.

### 4. Dukungan Pengamanan Sebelum Produksi

SATRIA dapat diarahkan sebagai gerbang keamanan pada alur CI/CD agar artefak release diperiksa sebelum dipromosikan ke staging atau production.

---

## Alur Singkat Hulu-ke-Hilir

### Tahap 1. Assessment Teknis

Target diuji melalui PANAH atau SATRIA sesuai jenisnya: container image, aplikasi web, server, API, repository, atau filesystem.

### Tahap 2. Orkestrasi dan Prioritisasi

SATRIA mengelola asset, hasil scan, severity, risk score, dan keputusan apakah temuan cukup dipantau lokal atau perlu dinaikkan menjadi ticket formal.

### Tahap 3. Eskalasi dan Penanganan

Temuan prioritas dikirim ke PERISAI untuk menjadi case aktif. Di sana SOC L1, L2, dan L3 mengelola triase, analisis, tasking, evidence, dan koordinasi lintas tim.

### Tahap 4. Remediasi dan Retest

Tim pengembang atau DevOps melakukan perbaikan. Setelah itu dilakukan retest untuk memastikan risiko sudah turun atau tertutup.

### Tahap 5. Penutupan dan Pelaporan

Case ditutup setelah bukti cukup, perbaikan tervalidasi, dan risiko residu dapat diterima. Seluruh jejak keputusan tetap terdokumentasi.

---

## Siapa Menggunakan Apa

### Tim Teknis

Menggunakan PANAH dan SATRIA untuk assessment, validasi target, evidence awal, dan orkestrasi scan.

### SOC

Menggunakan SATRIA untuk membaca temuan dan PERISAI untuk mengelola workflow ticket sampai penutupan.

### Pengembang dan DevOps

Menerima detail temuan atau case, melakukan perbaikan, dan mengirim bukti untuk retest.

### Pimpinan

Melihat posisi risiko, prioritas tindak lanjut, backlog ticket, dan progres penyelesaian secara ringkas.

---

## Hasil yang Diharapkan

- temuan kritikal tidak berhenti sebagai laporan;
- setiap tiket memiliki owner, task, dan evidence;
- keputusan eskalasi lebih cepat dan terukur;
- proses remediasi lebih terdokumentasi;
- organisasi memiliki jejak audit yang lebih kuat;
- promosi artefak ke produksi dapat dikendalikan melalui security gate.

---

## Pesan Kunci

Ekosistem `PANAH - SATRIA - PERISAI` bukan sekadar kumpulan tool, melainkan satu jalur operasional keamanan siber yang menghubungkan:

- pengujian teknis,
- prioritisasi risiko,
- pengambilan keputusan,
- penanganan insiden,
- dan verifikasi penutupan.

Dengan pendekatan ini, organisasi dapat bergerak dari model reaktif menjadi lebih terukur, terdokumentasi, dan siap diawasi secara manajerial.

