# Index Dokumentasi SATRIA

Dokumentasi ini disusun berurutan agar operator, pengembang, SOC, dan pimpinan dapat membaca alur SATRIA dari ringkasan sampai integrasi lanjutan.

## Dokumen Utama

| No. | Dokumen | Kegunaan |
|---|---|---|
| 01 | [Ringkasan SATRIA](01-RINGKASAN-SATRIA.md) | Gambaran umum fitur, menu, dan posisi SATRIA. |
| 02 | [SOP Hulu Hilir Per Tim](02-SOP-HULU-HILIR-PER-TIM.md) | Pembagian peran PANAH, SATRIA, PERISAI, SOC, Dev/Ops, dan stakeholder. |
| 03 | [Panduan Operasional SOC](03-PANDUAN-OPERASIONAL-SOC.md) | Cara kerja harian operator SOC dari aset sampai ticketing. |
| 04 | [Skenario Jenkins ke SATRIA](04-SKENARIO-JENKINS-KE-SATRIA.md) | Uji integrasi pipeline CI/CD dan security gate. |
| 05 | [Integrasi Wazuh ke PERISAI](05-INTEGRASI-WAZUH-KE-PERISAI.md) | Jalur alert Wazuh ke PERISAI / DFIR-IRIS. |
| 06 | [UR SATRIA Docker Compose](06-UR-001-SATRIA-DOCKER-COMPOSE.md) | Requirement dan catatan deployment Docker Compose. |
| 07 | [Integrasi AI SOC Wazuh, SATRIA, dan PERISAI](07-INTEGRASI-AI-SOC-WAZUH-SATRIA-PERISAI.md) | Rekomendasi penempatan AI SOC Wazuh, arsitektur, dan SOP integrasi. |

## Template Infrastruktur

| Template | Kegunaan |
|---|---|
| [Jenkins lokal untuk uji pipeline](../infra/jenkins-local/README.md) | Simulasi Jenkins yang memanggil API SATRIA. |
| [Template runtime AI SOC Wazuh](../infra/aisocwazuh/README.md) | Contoh deployment service pendamping AI SOC Wazuh. |

## Catatan Keamanan

Dokumentasi repository tidak boleh menyimpan kredensial, IP internal, password, token, atau API key produksi. Gunakan placeholder pada dokumen dan simpan nilai aktual di secret manager, file `.env` lokal yang tidak dicommit, atau credential store resmi.
