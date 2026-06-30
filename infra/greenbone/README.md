# Integrasi Greenbone/OpenVAS untuk SATRIA

OpenVAS/Greenbone adalah stack multi-service dan disarankan memakai Greenbone Community Containers dari upstream.

Referensi:

```text
https://greenbone.github.io/docs/latest/22.4/container/index.html
https://github.com/greenbone/openvas-scanner
```

Setelah Greenbone berjalan, isi `.env` SATRIA:

```env
GREENBONE_HOST=<host-gvmd-or-gsad>
GREENBONE_USERNAME=<username>
GREENBONE_PASSWORD=<password>
GREENBONE_VERIFY_SSL=false
```

MVP saat ini menyediakan `infra_va` profile sebagai placeholder/API-ready.
Pengembangan lanjutan perlu menambahkan connector GMP untuk:

1. membuat target;
2. membuat task scan;
3. menjalankan task;
4. polling status;
5. mengambil report XML/JSON;
6. parsing hasil ke format SATRIA finding.
