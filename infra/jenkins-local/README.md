# Jenkins untuk Uji Interkoneksi SATRIA

Direktori ini menyiapkan Jenkins berbasis Docker untuk kebutuhan uji pipeline ke SATRIA. Tujuannya adalah memberi lingkungan uji yang cepat bagi tim pengembang dan DevOps sebelum integrasi dipindahkan ke Jenkins production. Lingkungan lokal ini juga sudah diduplikasi ke Jenkins server untuk uji terpusat.

## Tujuan

- Menjalankan Jenkins lokal tanpa instalasi manual di host.
- Menyediakan pipeline contoh `satria-security-gate`.
- Menguji alur `intake release -> create scan -> polling -> gate -> publish ticket opsional`.
- Membuktikan bahwa SATRIA dapat dipakai sebagai security gate pada jalur build-release.

## Port bawaan

- Jenkins UI: `http://<JENKINS_LOCAL_HOST>:<JENKINS_LOCAL_PORT>`
- Jenkins agent port: `50088`

## Jenkins Server Terpusat

Jenkins hasil duplikasi lokal sudah tersedia pada server:

- Jenkins UI: `http://<JENKINS_SERVER_HOST>:<JENKINS_SERVER_PORT>`
- service: `jenkins-satria.service`
- job utama: `satria-security-gate`
- job demo lolos: `satria-gate-passed-demo`
- job demo gagal: `satria-gate-failed-demo`

Deployment server berjalan native melalui `systemd` karena runtime Docker/Podman pada host target belum tersedia. Konfigurasi integrasi SATRIA tetap sama dengan Jenkins lokal:

- `SATRIA_URL=http://<SATRIA_HOST>:<SATRIA_PORT>`
- `SATRIA_API_TOKEN=<satria-api-token>`
- `SATRIA_ASSET_CODE=JENKINS-DEMO`
- `SATRIA_ASSET_NAME=Jenkins Demo Service`

Perintah operasional di server Jenkins:

```bash
sudo systemctl status jenkins-satria.service
sudo journalctl -u jenkins-satria.service -f
```

## File penting

- `docker-compose.yml`: service Jenkins lokal
- `Dockerfile`: image Jenkins dengan `curl`, `python3`, `jq`, dan plugin pipeline
- `casc/jenkins.yaml`: konfigurasi Jenkins as Code dasar
- `init.groovy.d/seed-pipeline.groovy`: seed job yang membuat pipeline otomatis saat Jenkins boot
- `jobs/satria-security-gate.Jenkinsfile`: pipeline contoh yang memanggil SATRIA
- `.env.example`: contoh konfigurasi lokal

## Variabel yang perlu diisi

Salin `.env.example` menjadi `.env`, lalu sesuaikan minimal:

- `JENKINS_ADMIN_ID`
- `JENKINS_ADMIN_PASSWORD`
- `SATRIA_URL`
- `SATRIA_API_TOKEN`
- `SATRIA_ASSET_CODE`
- `SATRIA_ASSET_NAME`

Contoh:

```env
JENKINS_HTTP_PORT=8088
JENKINS_AGENT_PORT=50088
JENKINS_ADMIN_ID=<jenkins-admin-username>
JENKINS_ADMIN_PASSWORD=<jenkins-admin-password>
SATRIA_URL=http://<SATRIA_HOST>:<SATRIA_PORT>
SATRIA_API_TOKEN=<satria-api-token>
SATRIA_ASSET_CODE=JENKINS-DEMO
SATRIA_ASSET_NAME=Jenkins Demo Service
```

## Menjalankan

```powershell
cd infra\jenkins-local
Copy-Item .env.example .env
docker compose up -d --build
```

Lalu buka:

- Jenkins: `http://<JENKINS_LOCAL_HOST>:<JENKINS_LOCAL_PORT>`

Catatan keamanan:

- jangan simpan username admin, password admin, atau token SATRIA secara hardcode di repository;
- gunakan `.env` lokal yang tidak dikomit, Jenkins Credentials, atau secret manager organisasi.

## Job uji yang tersedia

Job `satria-security-gate` akan otomatis dibuat saat Jenkins pertama kali boot.

Parameter utamanya:

- `IMAGE_REF`: default `nginx:latest`
- `ASSET_CODE`: kode aset untuk intake release
- `ASSET_NAME`: nama aset pada SATRIA
- `SCAN_PROFILE`: `quick_container`, `full_container`, atau `sbom_scan`
- `ENVIRONMENT_TARGET`: `staging` atau `production`
- `PUBLISH_TO_IRIS`: `true/false`

## Apa yang dilakukan pipeline ini

Saat build dijalankan, Jenkins akan:

1. membuat `release-intake.json`
2. memanggil `POST /api/v1/releases/intake`
3. mengambil `asset_id` dan `release_id`
4. membuat scan job SATRIA melalui `POST /api/v1/scans`
5. polling status sampai selesai melalui `GET /api/v1/scans/{scan_id}`
6. mengambil hasil melalui `GET /api/v1/scans/{scan_id}/result`
7. membaca `decision`
8. memblokir pipeline bila SATRIA mengembalikan `blocked`
9. mengirim ticket ke IRIS bila opsi publish diaktifkan

## Cara login dan pemakaian awal

1. Buka Jenkins UI.
2. Login dengan akun admin lokal dari `.env`.
3. Buka job `satria-security-gate`.
4. Klik `Build with Parameters`.
5. Isi parameter uji.
6. Pantau console output build.

## Contoh parameter uji yang sudah berhasil

- `IMAGE_REF=nginx:latest`
- `ASSET_CODE=JENKINS-DEMO`
- `ASSET_NAME=Jenkins-Demo-Service`
- `SCAN_PROFILE=quick_container`
- `ENVIRONMENT_TARGET=staging`
- `PUBLISH_TO_IRIS=false`

## Hasil smoke test yang diharapkan

Integrasi dianggap berhasil bila:

- Jenkins berhasil membuat release intake di SATRIA
- Jenkins berhasil membuat scan job
- status scan dapat dipolling sampai `completed`
- hasil JSON dapat dibaca Jenkins
- SATRIA mengembalikan `allowed`, `need_approval`, atau `blocked`
- pipeline bereaksi sesuai keputusan tersebut

Catatan penting:

- Bila hasil akhir `blocked`, integrasi tetap dianggap berhasil.
- `blocked` berarti policy gate bekerja dan release memang ditahan.
- Pada Jenkins server, job `satria-gate-passed-demo` sudah tervalidasi `SUCCESS` dan `satria-gate-failed-demo` sudah tervalidasi `FAILURE`.

## Referensi lanjutan

- [Indeks dokumentasi SATRIA](C:/Users/gufroni/Documents/GitHub/satria/docs/README.md)
- [docs/06-SKENARIO-JENKINS-LOKAL-KE-SATRIA.md](C:/Users/gufroni/Documents/GitHub/satria/docs/06-SKENARIO-JENKINS-LOKAL-KE-SATRIA.md)
- [docs/08-AUDIT-UR-CICD-SATRIA-2026-07-04.md](C:/Users/gufroni/Documents/GitHub/satria/docs/08-AUDIT-UR-CICD-SATRIA-2026-07-04.md)
