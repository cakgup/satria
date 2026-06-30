# Desain Teknis MVP SATRIA

## Scope Implementasi Saat Ini

MVP ini mengimplementasikan:

- Asset inventory.
- Scan profile.
- Scan job queue berbasis Celery + Redis.
- PostgreSQL database.
- Dashboard FastAPI/Jinja.
- Normalizer hasil Trivy, Syft, Grype, ZAP, dan OpenVAS sample payload.
- Deduplikasi finding berdasarkan hash dedup key.
- Risk scoring berdasarkan severity + asset criticality + CVSS bila tersedia.
- Stub connector DFIR-IRIS.
- Docker Compose environment.

## Scanner Behavior

Worker akan menjalankan scanner CLI jika tersedia dan `SATRIA_DEMO_MODE=false`.
Jika scanner tidak tersedia atau target tidak masuk allowlist, worker membuat sample payload.

## Production Hardening Checklist

- Pasang SSO/OIDC/LDAP.
- Tambahkan RBAC penuh.
- Tambahkan TLS/reverse proxy.
- Pisahkan scanner worker network dari backend.
- Aktifkan allowlist target scan.
- Tambahkan approval untuk ZAP full scan dan OpenVAS scan.
- Enkripsi secret API key dan credential registry.
- Tambahkan backup database.
- Tambahkan retention policy raw report.
- Tambahkan observability dan log aggregation.
