# SATRIA MVP End-to-End Smoke Test Results

Tanggal uji: 2026-06-29

## Ruang Lingkup Uji

Smoke test dilakukan dari hulu ke hilir menggunakan mode demo lokal tanpa Docker daemon, PostgreSQL, Redis, scanner binary riil, OpenVAS riil, dan DFIR-IRIS riil. Tujuannya memastikan alur aplikasi SATRIA bekerja penuh secara fungsional:

1. Health check aplikasi.
2. Pendaftaran asset.
3. Pembuatan scan job.
4. Eksekusi scanner worker dalam demo mode.
5. Pembuatan raw scanner report JSON.
6. Normalisasi finding dari Trivy, Syft, Grype, OpenVAS, dan ZAP.
7. Penyimpanan hasil ke database.
8. Tampilan dashboard dan vulnerability summary.
9. Validasi pie chart severity berbasis CSS `conic-gradient`.
10. API summary.
11. Export laporan CSV.
12. Export laporan Excel `.xlsx`.
13. Generate executive report Markdown.
14. Kirim single finding ke DFIR-IRIS stub.
15. Bulk send Critical/High findings ke DFIR-IRIS stub.
16. Update status remediation.
17. Audit log.

## Perintah Uji

```bash
SATRIA_DEMO_MODE=true \
DATABASE_URL=sqlite:////tmp/satria_e2e_smoke.db \
CELERY_BROKER_URL=memory:// \
CELERY_RESULT_BACKEND=cache+memory:// \
REPORT_DIR=/tmp/satria_e2e_reports \
python scripts/e2e_smoke_test.py
```

## Hasil Uji

```text
SATRIA END-TO-END SMOKE TEST PASSED
- 01 health endpoint OK
- 02 asset intake and scan job creation OK
- 03 scanner worker, raw reports, normalizer, and DB persistence OK
- 04 dashboard pages and vulnerability summary severity pie OK
- 05 summary API OK
- 06 CSV, Excel, and executive Markdown reporting OK
- 07 DFIR-IRIS single and bulk ticketing workflow OK
- 08 remediation status update and audit log OK
- 09 raw scanner report JSON files OK (7 generated)
```

## Catatan Batasan Uji

Docker daemon tidak tersedia di environment pengujian ini, sehingga `docker compose up -d --build` belum dapat diuji langsung. Validasi yang sudah dilakukan adalah validasi YAML compose, compile Python, dan uji aplikasi lokal melalui FastAPI TestClient dengan SQLite.

Integrasi DFIR-IRIS pada smoke test memakai mode stub karena `IRIS_URL` dan `IRIS_API_KEY` belum dikonfigurasi. Saat dihubungkan ke DFIR-IRIS riil, perlu mengisi konfigurasi pada `.env`.

OpenVAS/Greenbone pada MVP masih connector-ready placeholder. Untuk scan riil, Greenbone Community Containers perlu dijalankan sebagai stack upstream dan connector GMP/API perlu dilengkapi.
