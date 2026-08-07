# Integrasi Wazuh ke PERISAI / DFIR-IRIS

## Navigasi Dokumen Terkait

- [Indeks dokumentasi SATRIA](README.md)
- [Panduan Operasional SOC](03-PANDUAN-OPERASIONAL-SOC.md)
- [Manual Book SATRIA](08-MANUAL-BOOK-SATRIA.md)
- [Integrasi AI SOC Wazuh](07-INTEGRASI-AI-SOC-WAZUH-SATRIA-PERISAI.md)

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

## Opsi Jalur Enrichment Dengan AI SOC Wazuh

Untuk pengembangan berikutnya, alert Wazuh tidak harus langsung dibuat menjadi case. Alert dapat lebih dulu melewati service AI SOC Wazuh agar data yang masuk ke PERISAI lebih bersih dan bernilai operasional.

Rekomendasi alur:

1. Wazuh menghasilkan alert.
2. AI SOC Wazuh melakukan enrichment, deduplikasi, dan risk scoring.
3. Alert yang memenuhi policy dikirim ke SATRIA untuk monitoring atau ke PERISAI sebagai case.
4. PERISAI tetap menjadi sistem utama untuk investigasi, task, evidence, dan penutupan case.

Detail pengembangan tersedia di [Integrasi AI SOC Wazuh dengan SATRIA dan PERISAI](07-INTEGRASI-AI-SOC-WAZUH-SATRIA-PERISAI.md).

---

## Notifikasi Telegram Untuk Alert Wazuh Level Tinggi

Selain dikirim ke PERISAI, alert Wazuh juga dapat dikirim ke grup Telegram melalui custom integration. Pola ini cocok untuk notifikasi cepat SOC, sedangkan detail investigasi tetap dilakukan di PERISAI.

Rekomendasi minimum:

- Kirim hanya alert penting, misalnya `rule.level >= 10`.
- Gunakan bot Telegram khusus SOC, bukan bot pribadi.
- Simpan `BOT_TOKEN` dan `CHAT_ID` hanya di server Wazuh atau secret manager.
- Jangan menyimpan token asli di repository Git.

### Prasyarat Telegram

1. Buat bot melalui `@BotFather`.
2. Simpan token bot sebagai `BOT_TOKEN`.
3. Tambahkan bot ke grup SOC.
4. Ambil `CHAT_ID` grup.
5. Pastikan server Wazuh dapat mengakses Telegram API:

```bash
curl -4 -sS --connect-timeout 10 https://api.telegram.org
```

Jika server berada di jaringan dengan proxy yang tidak stabil, gunakan koneksi direct pada script dengan opsi `--noproxy '*'`.

### Lokasi Template Script

Template pesan Telegram berada di script integrasi Wazuh:

```text
/var/ossec/integrations/custom-telegram.py
```

Bagian yang biasanya diedit adalah fungsi `build_message()`. Contoh header formal:

```python
fields = [
    "<b>Wazuh Alert</b>",
    "------------------",
    f"<b>Level:</b> {html.escape(str(rule_level))}",
    f"<b>Rule ID:</b> {html.escape(str(rule_id))}",
    f"<b>Rule:</b> {html.escape(str(description))}",
]
```

### Contoh Script `custom-telegram.py`

Buat file berikut di server Wazuh:

```bash
sudo vi /var/ossec/integrations/custom-telegram.py
```

Isi contoh:

```python
#!/usr/bin/env python3
import html
import json
import subprocess
import sys

BOT_TOKEN = "ISI_DENGAN_BOT_TOKEN"
CHAT_ID = "ISI_DENGAN_CHAT_ID"
MAX_MESSAGE_LEN = 3900


def load_alert(path):
    with open(path, "r", encoding="utf-8", errors="replace") as alert_file:
        return json.load(alert_file)


def value_at(data, *keys, default="-"):
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    if current in (None, ""):
        return default
    return current


def build_message(alert):
    rule_level = value_at(alert, "rule", "level")
    rule_id = value_at(alert, "rule", "id")
    description = value_at(alert, "rule", "description", default="Wazuh alert")
    agent_name = value_at(alert, "agent", "name")
    agent_id = value_at(alert, "agent", "id")
    agent_ip = value_at(alert, "agent", "ip")
    manager_name = value_at(alert, "manager", "name")
    location = value_at(alert, "location")
    timestamp = value_at(alert, "timestamp")
    full_log = value_at(alert, "full_log")

    fields = [
        "<b>Wazuh Alert</b>",
        "------------------",
        f"<b>Level:</b> {html.escape(str(rule_level))}",
        f"<b>Rule ID:</b> {html.escape(str(rule_id))}",
        f"<b>Rule:</b> {html.escape(str(description))}",
        f"<b>Agent:</b> {html.escape(str(agent_name))} ({html.escape(str(agent_id))})",
        f"<b>Agent IP:</b> {html.escape(str(agent_ip))}",
        f"<b>Manager:</b> {html.escape(str(manager_name))}",
        f"<b>Location:</b> {html.escape(str(location))}",
        f"<b>Time:</b> {html.escape(str(timestamp))}",
        "",
        f"<b>Log:</b> <code>{html.escape(str(full_log)[:1200])}</code>",
    ]
    return "\n".join(fields)[:MAX_MESSAGE_LEN]


def send_telegram(message):
    command = [
        "/usr/bin/curl",
        "-4",
        "-sS",
        "--noproxy", "*",
        "--connect-timeout", "10",
        "--max-time", "20",
        "-X", "POST",
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        "-d", f"chat_id={CHAT_ID}",
        "-d", "parse_mode=HTML",
        "-d", "disable_web_page_preview=true",
        "--data-urlencode", f"text={message}",
    ]
    result = subprocess.run(command, text=True, capture_output=True, timeout=25)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    response = json.loads(result.stdout)
    if not response.get("ok"):
        raise RuntimeError(result.stdout)


def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: custom-telegram.py <alert_json>")
    alert = load_alert(sys.argv[1])
    send_telegram(build_message(alert))


if __name__ == "__main__":
    main()
```

Atur owner dan permission:

```bash
sudo chown root:wazuh /var/ossec/integrations/custom-telegram.py
sudo chmod 750 /var/ossec/integrations/custom-telegram.py
sudo python3 -m py_compile /var/ossec/integrations/custom-telegram.py
```

### Konfigurasi `ossec.conf`

Backup konfigurasi sebelum mengubah:

```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup-telegram-$(date +%Y%m%d-%H%M%S)
```

Tambahkan blok berikut di `/var/ossec/etc/ossec.conf`:

```xml
<!-- Telegram notification for high-severity Wazuh alerts -->
<integration>
    <name>custom-telegram.py</name>
    <level>10</level>
    <alert_format>json</alert_format>
</integration>
```

Catatan:

- `<level>10</level>` berarti Wazuh menjalankan integrasi untuk alert level 10 ke atas.
- Jika hanya ingin rule tertentu, tambahkan `<rule_id>...</rule_id>` sesuai kebutuhan.
- Integrasi Telegram dapat berjalan berdampingan dengan `custom-iris.py`.

Restart Wazuh Manager:

```bash
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

Status yang diharapkan:

```text
active
```

### Smoke Test Telegram

Buat payload uji:

```bash
cat > /tmp/test-telegram-alert.json <<'JSON'
{
  "timestamp": "2026-08-04T10:52:00+0700",
  "rule": {
    "level": 10,
    "id": "999999",
    "description": "Test notifikasi Telegram Wazuh level 10"
  },
  "agent": {
    "id": "000",
    "name": "Wazuh Manager",
    "ip": "127.0.0.1"
  },
  "manager": {
    "name": "Wazuh Manager"
  },
  "location": "manual-test",
  "full_log": "Test integrasi Telegram dari Wazuh."
}
JSON
```

Jalankan script:

```bash
sudo /var/ossec/integrations/custom-telegram.py /tmp/test-telegram-alert.json
```

Jika berhasil, grup Telegram menerima pesan dengan format:

```text
Wazuh Alert
------------------
Level: 10
Rule ID: 999999
Rule: Test notifikasi Telegram Wazuh level 10
```

### Troubleshooting Telegram

#### 1. Pesan menampilkan `?? Wazuh Alert`

Penyebab:

- Emoji tidak ter-render sempurna di client Telegram atau terminal tertentu.

Perbaikan:

- Hapus emoji pada `build_message()`.
- Gunakan header teks formal:

```python
"<b>Wazuh Alert</b>",
"------------------",
```

#### 2. Script timeout ketika dijalankan oleh Wazuh atau `sudo`

Penyebab umum:

- Environment root menggunakan proxy yang tidak bisa menjangkau Telegram.

Cek:

```bash
sudo env | grep -i proxy
```

Perbaikan:

- Gunakan opsi `--noproxy '*'` pada command `curl` di script.

#### 3. Bot tidak mengirim pesan ke grup

Pastikan:

- Bot sudah ditambahkan ke grup.
- `CHAT_ID` benar dan biasanya bernilai negatif untuk grup.
- Token bot valid.
- Server dapat mengakses `api.telegram.org:443`.

#### 4. Integrasi tidak aktif setelah restart

Cek log:

```bash
sudo tail -n 120 /var/ossec/logs/ossec.log | grep -iE 'custom-telegram|integratord|error'
```

Log yang diharapkan:

```text
wazuh-integratord: INFO: Enabling integration for: 'custom-telegram.py'.
```

---

## Email Alert Dengan SMTP2GO Authenticated SMTP

Jika SMTP internal organisasi menolak relay tanpa autentikasi, Wazuh dapat mengirim email melalui SMTP2GO menggunakan custom integration. Jalur ini berbeda dari `wazuh-maild` bawaan karena script dapat memakai username/password SMTP dan port SSL seperti `443`.

Gunakan opsi ini bila ditemukan error seperti:

```text
wazuh-maild: ERROR: Mail from not accepted by server
SMTP; Client was not authenticated to send anonymous mail during MAIL FROM
```

### Prasyarat SMTP2GO

- Akun SMTP2GO sudah dibuat.
- SMTP user sudah tersedia di `Sending > SMTP Users`.
- Sender email sudah diverifikasi di `Sending > Verified Senders`.
- Server Wazuh dapat mengakses `mail.smtp2go.com` pada port yang diizinkan jaringan.

Contoh cek port:

```bash
for port in 2525 587 8025 80 25 465 443; do
  timeout 8 bash -c "</dev/tcp/mail.smtp2go.com/$port" >/dev/null 2>&1 \
    && echo "OPEN:$port" || echo "CLOSED:$port"
done
```

Jika port SMTP umum diblokir tetapi port `443` terbuka, gunakan `SMTP_SSL` di port `443`.

### Lokasi Script

Script integrasi disimpan di:

```text
/var/ossec/integrations/custom-email-smtp2go.py
```

Contoh konfigurasi credential di dalam script:

```python
SMTP_HOST = "mail.smtp2go.com"
SMTP_PORT = 443
SMTP_USERNAME = "ISI_DENGAN_SMTP_USERNAME"
SMTP_PASSWORD = "ISI_DENGAN_SMTP_PASSWORD"
EMAIL_FROM = "sender-yang-sudah-diverifikasi@example.com"
EMAIL_TO = "soc@example.com"
REPLY_TO = "soc@example.com"
MIN_LEVEL = 10
```

Untuk beberapa penerima, gunakan list:

```python
EMAIL_TO = [
    "soc-l1@example.com",
    "soc-l2@example.com",
    "incident-manager@example.com",
]
```

Kemudian set header `To` dengan `join`:

```python
message["To"] = ", ".join(EMAIL_TO) if isinstance(EMAIL_TO, list) else EMAIL_TO
```

Gunakan placeholder pada dokumentasi. Nilai asli hanya boleh berada di server Wazuh atau secret manager.

### Contoh Script Minimal

```python
#!/usr/bin/env python3
import json
import smtplib
import ssl
import sys
from email.message import EmailMessage

SMTP_HOST = "mail.smtp2go.com"
SMTP_PORT = 443
SMTP_USERNAME = "ISI_DENGAN_SMTP_USERNAME"
SMTP_PASSWORD = "ISI_DENGAN_SMTP_PASSWORD"
EMAIL_FROM = "sender-yang-sudah-diverifikasi@example.com"
EMAIL_TO = [
    "soc-l1@example.com",
    "soc-l2@example.com",
]
REPLY_TO = "soc@example.com"
MIN_LEVEL = 10
MAX_LOG_LEN = 2500


def load_alert(path):
    with open(path, "r", encoding="utf-8", errors="replace") as alert_file:
        return json.load(alert_file)


def value_at(data, *keys, default="-"):
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    if current in (None, ""):
        return default
    return current


def rule_level(alert):
    try:
        return int(value_at(alert, "rule", "level", default=0))
    except (TypeError, ValueError):
        return 0


def build_subject(alert):
    level = rule_level(alert)
    rule_id = value_at(alert, "rule", "id")
    description = value_at(alert, "rule", "description", default="Wazuh alert")
    agent_name = value_at(alert, "agent", "name")
    return f"[Wazuh][Level {level}][Rule {rule_id}] {agent_name} - {description}"[:180]


def build_body(alert):
    level = rule_level(alert)
    rule_id = value_at(alert, "rule", "id")
    description = value_at(alert, "rule", "description", default="Wazuh alert")
    agent_name = value_at(alert, "agent", "name")
    agent_id = value_at(alert, "agent", "id")
    agent_ip = value_at(alert, "agent", "ip")
    manager_name = value_at(alert, "manager", "name")
    location = value_at(alert, "location")
    timestamp = value_at(alert, "timestamp")
    full_log = str(value_at(alert, "full_log"))[:MAX_LOG_LEN]
    alert_id = value_at(alert, "id")

    return "\n".join([
        "Wazuh Alert",
        "------------------",
        f"Level     : {level}",
        f"Rule ID   : {rule_id}",
        f"Rule      : {description}",
        f"Agent     : {agent_name} ({agent_id})",
        f"Agent IP  : {agent_ip}",
        f"Manager   : {manager_name}",
        f"Location  : {location}",
        f"Time      : {timestamp}",
        f"Alert ID  : {alert_id}",
        "",
        "Log:",
        full_log,
        "",
        "Pesan ini dikirim otomatis oleh Wazuh Manager.",
    ])


def send_email(alert):
    message = EmailMessage()
    message["Subject"] = build_subject(alert)
    message["From"] = EMAIL_FROM
    message["To"] = ", ".join(EMAIL_TO) if isinstance(EMAIL_TO, list) else EMAIL_TO
    message["Reply-To"] = REPLY_TO
    message.set_content(build_body(alert))

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30, context=context) as smtp:
        smtp.ehlo()
        smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
        smtp.send_message(message)


def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: custom-email-smtp2go.py <alert_json>")
    alert = load_alert(sys.argv[1])
    if rule_level(alert) < MIN_LEVEL:
        return
    send_email(alert)


if __name__ == "__main__":
    main()
```

Atur permission:

```bash
sudo chown root:wazuh /var/ossec/integrations/custom-email-smtp2go.py
sudo chmod 750 /var/ossec/integrations/custom-email-smtp2go.py
sudo python3 -m py_compile /var/ossec/integrations/custom-email-smtp2go.py
```

### Konfigurasi `ossec.conf`

Tambahkan blok integrasi:

```xml
<!-- Authenticated SMTP2GO email notification for high-severity Wazuh alerts -->
<integration>
    <name>custom-email-smtp2go.py</name>
    <level>10</level>
    <alert_format>json</alert_format>
</integration>
```

Jika custom email sudah dipakai, nonaktifkan email bawaan Wazuh agar tidak muncul error SMTP internal:

```xml
<email_notification>no</email_notification>
```

Restart Wazuh:

```bash
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

Log yang diharapkan:

```text
wazuh-integratord: INFO: Enabling integration for: 'custom-email-smtp2go.py'.
```

### Smoke Test Email

Buat payload uji:

```bash
cat > /tmp/test-email-alert.json <<'JSON'
{
  "timestamp": "2026-08-04T13:50:00+0700",
  "rule": {
    "level": 10,
    "id": "999998",
    "description": "Test email SMTP2GO Wazuh level 10"
  },
  "agent": {
    "id": "000",
    "name": "Wazuh Manager",
    "ip": "127.0.0.1"
  },
  "manager": {
    "name": "Wazuh Manager"
  },
  "location": "manual-test",
  "id": "manual-smtp2go-test",
  "full_log": "Test integrasi email SMTP2GO dari Wazuh."
}
JSON
```

Jalankan:

```bash
sudo /var/ossec/integrations/custom-email-smtp2go.py /tmp/test-email-alert.json
```

Jika command selesai tanpa error, cek inbox tujuan dan folder spam/quarantine.

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
- [ ] Jika Telegram digunakan, `custom-telegram.py` berhasil mengirim smoke test.
- [ ] Token Telegram tidak tercatat di repository atau log publik.
- [ ] Jika SMTP2GO digunakan, sender email sudah verified.
- [ ] Jika SMTP2GO digunakan, `custom-email-smtp2go.py` berhasil mengirim smoke test.

---

## Catatan Keamanan

- Jangan menaruh password, API key, atau token asli di repository.
- Gunakan secret manager, environment variable, atau file konfigurasi server yang tidak ikut commit.
- Batasi level alert yang dikirim agar PERISAI tidak penuh oleh noise.
- Batasi notifikasi Telegram ke alert prioritas agar grup SOC tidak mengalami alert fatigue.
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
