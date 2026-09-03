# Operasional OWASP WSTG Assessment

Modul tersedia pada `/assessments` setelah aplikasi diperbarui dan backend dijalankan ulang. Gunakan sesi login SATRIA.

## Pembaruan instalasi Docker Compose

1. Buat backup database PostgreSQL dan source aplikasi dengan prosedur operasional yang berlaku.
2. Pastikan tidak ada pemindaian aktif sebelum memperbarui worker.
3. Ambil versi repository yang akan dipasang, lalu jalankan:

```sh
docker compose build satria-backend satria-worker
docker compose up -d --no-deps satria-backend satria-worker
```

Startup menambahkan tabel assessment yang belum ada. Data aset, temuan, dan tiket lama tetap digunakan. Database WSTG Compass standalone tidak diimpor otomatis. File gambar assessment disimpan dalam database SATRIA, sehingga ikut backup database.

## Validasi

```sh
python scripts/test_assessments.py
python scripts/check_cvss_reference.py
```

Pengujian pertama menggunakan database SQLite sementara dan memeriksa autentikasi, checklist, evidence, RoE, temuan, ekspor, dan perlindungan tiket. Pengujian kedua memerlukan Node.js dan membandingkan 4.096 vector antara implementasi Python dengan engine FIRST yang disertakan. Tidak memerlukan akses ke database produksi.

Periksa `/health`, halaman Assessments, serta layanan worker setelah pemasangan. Untuk rollback aplikasi, gunakan source dan image rilis sebelumnya; pertahankan database agar aktivitas yang baru dibuat tidak hilang.

## RoE dan tindak lanjut

RoE mencakup target, batasan, jadwal, aktivitas yang diizinkan/dilarang, kontak, dan kondisi penghentian pengujian. Perubahan teks melalui **Ubah RoE** dicatat dalam audit log. Fitur ini mendokumentasikan aturan; tidak menyediakan workflow persetujuan formal atau enforcement otomatis terhadap scanner.

Temuan manual menggunakan sumber `manual-wstg`, muncul di Findings dan Report, serta menggunakan alur Tickets yang sudah tersedia. Pengiriman ke IRIS dilakukan melalui tindakan pengguna. Penghapusan assessment/temuan ditolak jika temuan sudah terkait tiket atau alert IRIS.
