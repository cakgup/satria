# Integrasi DFIR-IRIS untuk SATRIA

DFIR-IRIS resmi disarankan dijalankan menggunakan Docker Compose dari repository upstream:

```bash
git clone https://github.com/dfir-iris/iris-web.git
cd iris-web
git checkout v2.4.20
cp .env.model .env
docker compose pull
docker compose up -d
```

Setelah IRIS berjalan, isi `.env` SATRIA:

```env
IRIS_URL=https://<host-iris>
IRIS_API_KEY=<api-key-service-account>
IRIS_VERIFY_SSL=false
```

MVP SATRIA menyediakan function `send_finding_to_iris()` di `app/iris.py`.
Jika `IRIS_URL`/`IRIS_API_KEY` kosong, aplikasi memakai stub ID `IRIS-STUB-*` agar workflow tetap bisa diuji.

## Pengembangan Lanjutan

1. Buat service account di DFIR-IRIS dengan permission alert read/write.
2. Mapping severity SATRIA ke severity ID lokal DFIR-IRIS.
3. Kirim finding Critical/High sebagai alert.
4. Tambahkan opsi create case dan upload raw report sebagai evidence.
5. Simpan `iris_alert_id`, `iris_case_id`, dan status sinkronisasi.
