# Template Runtime AI SOC Wazuh

Template ini menyiapkan pola deployment `aisocwazuh` sebagai service pendamping untuk integrasi Wazuh, SATRIA, dan PERISAI.

## Rekomendasi Penempatan

Untuk fase awal, jalankan container ini di server SATRIA/PUSAKA agar dekat dengan API SATRIA dan PERISAI. Jangan membebani Wazuh Manager dengan proses AI, korelasi berat, atau retry API.

## Struktur

- `.env.example` berisi contoh environment tanpa kredensial asli.
- `docker-compose.aisocwazuh.example.yml` berisi contoh service container.
- Folder input alert dapat dimount read-only dari export Wazuh atau mekanisme forwarder internal.

## Cara Pakai

1. Siapkan source project `aisocwazuh` di host runtime.
2. Salin `.env.example` menjadi `.env`.
3. Isi nilai environment memakai credential store atau secret internal.
4. Jalankan compose contoh.

```powershell
Copy-Item .env.example .env
docker compose -f docker-compose.aisocwazuh.example.yml up -d
docker compose -f docker-compose.aisocwazuh.example.yml logs -f aisocwazuh
```

## Variabel Penting

- `AISOC_MODE`: `mock`, `hybrid`, atau `real`.
- `WAZUH_API_URL`: URL Wazuh API.
- `SATRIA_BASE_URL`: URL API SATRIA.
- `PERISAI_BASE_URL`: URL PERISAI atau DFIR-IRIS.
- `SATRIA_SERVICE_TOKEN`: token service account SATRIA.
- `PERISAI_API_KEY`: API key PERISAI bila jalur direct publish dipakai.

## Catatan Keamanan

Repository ini tidak menyimpan IP internal, username, password, token, atau API key produksi. Nilai aktual harus dikelola melalui `.env` lokal, Docker secret, atau secret manager organisasi.

## Dokumentasi Terkait

- [Integrasi AI SOC Wazuh dengan SATRIA dan PERISAI](../../docs/07-INTEGRASI-AI-SOC-WAZUH-SATRIA-PERISAI.md)
- [Integrasi Wazuh ke PERISAI](../../docs/05-INTEGRASI-WAZUH-KE-PERISAI.md)
