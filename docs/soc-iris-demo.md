# SATRIA + DFIR-IRIS Demo SOP

## Akses

- SATRIA: `http://127.0.0.1:8090`
- DFIR-IRIS: `https://127.0.0.1:10443`
- IRIS admin:
  - username: `administrator`
  - password: `SATRIA-IRIS-Admin!2026`

## User Demo SOC

- L1: `cakgup1` / `Cakgup1!2026`
- L2: `cakgup2` / `Cakgup2!2026`
- L3: `cakgup3` / `Cakgup3!2026`

Ketiga user sudah dibuat di DFIR-IRIS dan dimasukkan ke grup `Analysts`.

## Case Demo Yang Sudah Tersinkron

- IRIS Case `#2`: `Insiden phishing pada salah satu KPPN`
- IRIS Case `#3`: `Insiden malware pada laptop pegawai KPPN`

Di masing-masing case sudah tersinkron:

- case metadata dari SATRIA
- task L1, L2, L3
- activity/timeline
- evidence record
- upload file evidence ke datastore IRIS

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
