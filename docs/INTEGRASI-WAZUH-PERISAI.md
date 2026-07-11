# Integrasi Wazuh ke PERISAI / DFIR-IRIS

## Navigasi Dokumen Terkait

- [Indeks dokumentasi SATRIA](C:/Users/gufroni/Documents/GitHub/satria/docs/README.md)
- [Panduan Operasional SOC](C:/Users/gufroni/Documents/GitHub/satria/docs/OPERASIONAL-SOC.md)
- [Walkthrough IRIS untuk Top Management](C:/Users/gufroni/Documents/GitHub/satria/docs/IRIS-TOP-MANAGEMENT-WALKTHROUGH.md)

Dokumen ini menjelaskan konfigurasi integrasi Wazuh Manager ke PERISAI berbasis DFIR-IRIS agar alert dari Wazuh dapat diteruskan ke sistem ticketing dan investigasi insiden.

PERISAI diposisikan sebagai sistem utama untuk pengelolaan alert, case, task, evidence, dan tindak lanjut insiden. Wazuh tetap menjadi sumber deteksi keamanan, sedangkan PERISAI menjadi tempat triase dan investigasi lanjutan.

---

## Ringkasan Arsitektur

```text
Wazuh Agent / Manager
        |
        | alert JSON level tertentu
        v
Wazuh Integration custom-iris.py
        |
        | HTTPS POST
        v
PERISAI / DFIR-IRIS
        |
        v
Alert, triage, case, task, evidence, dan closure
```

Alur kerjanya:

1. Wazuh menghasilkan alert berdasarkan rule dan level.
2. Wazuh Manager menjalankan integrasi `custom-iris.py`.
3. Script membaca payload alert JSON dari Wazuh.
4. Script melakukan normalisasi field agar cocok dengan API DFIR-IRIS.
5. Script mengirim alert ke endpoint PERISAI.
6. PERISAI menerima alert untuk diproses oleh analis SOC.

---

## Prasyarat

- Wazuh Manager sudah aktif.
- PERISAI / DFIR-IRIS sudah aktif dan dapat diakses dari server Wazuh.
- Endpoint alert PERISAI sudah tersedia, misalnya:

```text
https://<PERISAI_HOST>:<PORT>/alerts/add
```

- API key IRIS tersedia dan valid.
- Server Wazuh dapat melakukan koneksi HTTPS ke endpoint PERISAI.
- Script integrasi Wazuh tersedia di:

```text
/var/ossec/integrations/custom-iris.py
```

---

## Konfigurasi Wazuh

Edit file konfigurasi Wazuh Manager:

```bash
sudo vi /var/ossec/etc/ossec.conf
```

Tambahkan blok integrasi berikut:

```xml
<!-- PERISAI / DFIR-IRIS integration -->
<integration>
    <name>custom-iris.py</name>
    <hook_url>https://PERISAI_HOST:8092/alerts/add</hook_url>
    <level>3</level>
    <api_key>ISI_DENGAN_API_KEY_IRIS</api_key>
    <alert_format>json</alert_format>
</integration>
```

Catatan penting:

- Gunakan `https://` bila port PERISAI berjalan sebagai HTTPS.
- Jangan memakai `http://` pada port HTTPS karena akan menghasilkan error `400 Bad Request`.
- Nilai `<level>3</level>` berarti alert level 3 ke atas akan dikirim. Untuk operasional yang lebih tenang, pertimbangkan level lebih tinggi seperti `7`, `10`, atau filter tambahan.
- Jangan menyimpan API key asli pada repository Git.

Setelah konfigurasi diubah, restart Wazuh Manager:

```bash
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

Status yang diharapkan:

```text
active
```

---

## Script Integrasi `custom-iris.py`

Script integrasi harus:

- menerima argumen dari Wazuh;
- membaca file alert JSON;
- mengambil `api_key` dan `hook_url`;
- melakukan mapping severity;
- mengisi fallback untuk field Wazuh yang tidak selalu ada;
- mengirim HTTP POST ke endpoint PERISAI;
- mencatat hasil ke log integrasi.

Lokasi script:

```text
/var/ossec/integrations/custom-iris.py
```

Permission yang disarankan:

```bash
sudo chown root:wazuh /var/ossec/integrations/custom-iris.py
sudo chmod 750 /var/ossec/integrations/custom-iris.py
```

Field Wazuh yang harus dianggap opsional:

- `agent.ip`
- `data`
- `full_log`
- `location`
- `rule.groups`
- `rule.mitre`

Script tidak boleh langsung mengakses field opsional dengan pola seperti:

```python
alert_json["agent"]["ip"]
alert_json["data"]
```

Gunakan `.get()` atau fallback agar integrasi tidak gagal saat alert memiliki struktur berbeda.

---

## Mapping Data ke PERISAI

Contoh field yang dikirim ke PERISAI:

| Field PERISAI / IRIS | Sumber dari Wazuh |
| --- | --- |
| `alert_title` | `rule.description` |
| `alert_description` | ringkasan rule, agent, lokasi, dan log |
| `alert_source` | `Wazuh` |
| `alert_source_ref` | `id` alert Wazuh |
| `alert_source_link` | URL dashboard Wazuh |
| `alert_severity_id` | hasil mapping dari `rule.level` |
| `alert_status_id` | status awal alert |
| `alert_source_event_time` | `timestamp` |
| `alert_tags` | `groups`, `mitre`, dan metadata lain |
| `alert_source_content` | payload JSON asli |

Contoh mapping severity:

| Level Wazuh | Severity IRIS |
| --- | --- |
| 0-2 | Informational / Low |
| 3-6 | Low / Medium |
| 7-10 | Medium / High |
| 11-15 | High / Critical |

Mapping dapat disesuaikan dengan kebijakan SOC.

---

## Smoke Test Manual

Smoke test manual digunakan untuk memastikan script dapat mengirim alert ke PERISAI tanpa menunggu alert asli.

Contoh file alert dummy:

```bash
cat > /tmp/perisai-wazuh-smoke.alert <<'JSON'
{
  "timestamp": "2026-07-11T12:37:00+07:00",
  "id": "perisai-wazuh-smoke-20260711-1237",
  "rule": {
    "level": 5,
    "description": "PERISAI Wazuh smoke test",
    "groups": ["wazuh", "smoke-test"]
  },
  "agent": {
    "id": "001",
    "name": "wazuh-smoke-agent"
  },
  "manager": {
    "name": "wazuh-manager"
  },
  "location": "smoke-test",
  "full_log": "Synthetic Wazuh alert for PERISAI integration smoke test"
}
JSON
```

Jalankan script:

```bash
sudo /var/ossec/integrations/custom-iris.py \
  /tmp/perisai-wazuh-smoke.alert \
  "ISI_DENGAN_API_KEY_IRIS" \
  "https://PERISAI_HOST:8092/alerts/add"
```

Hasil yang diharapkan:

```text
exit code 0
HTTP status 200
```

Lihat log:

```bash
sudo tail -n 30 /var/ossec/logs/integrations.log
```

Contoh hasil sukses:

```text
custom-iris: POST https://PERISAI_HOST:8092/alerts/add status=200 ref=perisai-wazuh-smoke-20260711-1237 title='PERISAI Wazuh smoke test'
```

---

## Validasi dari Jalur Wazuh Manager

Setelah smoke test manual berhasil, pastikan integrasi juga berjalan dari Wazuh Manager.

Periksa log Wazuh:

```bash
sudo grep -n -E 'custom-iris|KeyError|Unable to run integration|Exit status' /var/ossec/logs/ossec.log | tail -n 40
```

Tidak boleh ada error baru seperti:

```text
KeyError: 'ip'
KeyError: 'data'
Unable to run integration for custom-iris.py
Exit status was: 1
```

Periksa log integrasi:

```bash
sudo tail -n 50 /var/ossec/logs/integrations.log
```

Jika alert asli terkirim, log akan berisi POST sukses ke endpoint PERISAI.

---

## Troubleshooting

### 1. Error `plain HTTP request was sent to HTTPS port`

Penyebab:

- `hook_url` memakai `http://` padahal endpoint berjalan di HTTPS.

Perbaikan:

```xml
<hook_url>https://PERISAI_HOST:8092/alerts/add</hook_url>
```

### 2. Error `KeyError: 'ip'`

Penyebab:

- Script menganggap semua alert memiliki `agent.ip`.
- Beberapa alert Wazuh tidak memiliki field IP agent.

Perbaikan:

- Gunakan fallback:

```python
agent = alert_json.get("agent", {})
agent_ip = agent.get("ip", "-")
```

### 3. Error `KeyError: 'data'`

Penyebab:

- Tidak semua alert Wazuh memiliki field `data`.

Perbaikan:

```python
data = alert_json.get("data", {})
```

### 4. PERISAI tidak menerima alert

Langkah cek:

```bash
curl -k -i https://PERISAI_HOST:8092/alerts/add
sudo tail -n 50 /var/ossec/logs/integrations.log
sudo tail -n 50 /var/ossec/logs/ossec.log
```

Pastikan:

- Wazuh Manager aktif.
- Endpoint PERISAI benar.
- API key valid.
- Script punya permission eksekusi.
- Tidak ada firewall yang memblokir akses dari Wazuh ke PERISAI.

### 5. Alert terlalu banyak masuk ke PERISAI

Penyebab:

- Level integrasi terlalu rendah, misalnya level `3`.

Opsinya:

- Naikkan level menjadi `7` atau `10`.
- Tambahkan filter rule/group di script.
- Buat allowlist rule tertentu yang boleh dikirim ke PERISAI.

---

## Checklist Operasional

Gunakan checklist berikut setelah konfigurasi:

- [ ] Endpoint memakai `https://` sesuai port PERISAI.
- [ ] API key IRIS valid.
- [ ] `custom-iris.py` berada di `/var/ossec/integrations/`.
- [ ] Owner script adalah `root:wazuh`.
- [ ] Permission script adalah `750`.
- [ ] Wazuh Manager berhasil restart.
- [ ] Smoke test manual berhasil `status=200`.
- [ ] Log Wazuh tidak menampilkan `KeyError`.
- [ ] Alert uji terlihat di halaman alert PERISAI.
- [ ] Level/filter alert sudah sesuai kebutuhan operasional SOC.

---

## Catatan Keamanan

- Jangan menaruh password, API key, atau token asli di repository.
- Gunakan secret manager, environment variable, atau file konfigurasi server yang tidak ikut commit.
- Batasi level alert yang dikirim agar PERISAI tidak penuh oleh noise.
- Untuk production, validasi sertifikat TLS sebaiknya diaktifkan dengan CA internal yang benar.
- Audit log integrasi secara berkala untuk memastikan tidak ada retry gagal atau flood alert.

---

## Hasil Validasi Terakhir

Validasi terakhir menunjukkan:

- Wazuh Manager aktif.
- Smoke test manual berhasil mengirim alert ke PERISAI dengan HTTP status `200`.
- Alert nyata dari Wazuh juga berhasil terkirim ke PERISAI.
- Error lama terkait `http://` ke port HTTPS dan `KeyError` field opsional sudah ditangani.

Dokumen ini dapat digunakan sebagai SOP awal integrasi Wazuh ke PERISAI dan diperluas sesuai kebijakan SOC yang berlaku.
