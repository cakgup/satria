from __future__ import annotations

from .config import get_settings

settings = get_settings()

SOC_DEMO_USERS = {
    "L1": settings.soc_l1_user,
    "L2": settings.soc_l2_user,
    "L3": settings.soc_l3_user,
}

IRIS_ROLE_PERMISSION_BLUEPRINT = {
    "SOC L1": {
        "description": "Triage awal, intake, containment cepat, dan eskalasi ke L2.",
        "permissions": [
            "standard_user",
            "alerts_read",
            "alerts_write",
            "customers_read",
            "activities_read",
            "search_across_cases",
        ],
    },
    "SOC L2": {
        "description": "Analisis teknis, scoping insiden, korelasi IOC, dan containment lanjutan.",
        "permissions": [
            "standard_user",
            "alerts_read",
            "alerts_write",
            "customers_read",
            "activities_read",
            "all_activities_read",
            "search_across_cases",
            "case_templates_read",
        ],
    },
    "SOC L3": {
        "description": "Lead responder untuk eradikasi, root cause analysis, recovery, dan pengembangan template respons.",
        "permissions": [
            "standard_user",
            "alerts_read",
            "alerts_write",
            "customers_read",
            "activities_read",
            "all_activities_read",
            "search_across_cases",
            "case_templates_read",
            "case_templates_write",
        ],
    },
}

IRIS_CASE_CLASSIFICATIONS = {
    "scanner-finding": "Vulnerable: Vulnerable Service",
    "malware-endpoint": "Malicious Code: Trojan Malware",
    "phishing-email": "Fraud: Phishing",
}


MANUAL_PLAYBOOKS: dict[str, dict] = {
    "virus_laptop_kppn": {
        "title": "Insiden malware pada laptop pegawai KPPN",
        "organization_unit": "KPPN",
        "incident_type": "malware-endpoint",
        "priority": "high",
        "source_channel": "soc-monitoring",
        "playbook": "SOC-MALWARE-ENDPOINT",
        "description": (
            "Pegawai KPPN melaporkan laptop menjadi lambat, muncul notifikasi antivirus, "
            "dan terdapat file mencurigakan yang mencoba melakukan koneksi keluar. "
            "Case ini diproses sebagai dugaan malware endpoint sampai terbukti sebaliknya."
        ),
        "tasks": [
            ("L1", "cakgup1", "Triage awal alert endpoint, validasi gejala, dan isolasi perangkat dari jaringan."),
            ("L2", "cakgup2", "Analisis IOC, hash file, persistence, dan sebaran artefak pada endpoint terkait."),
            ("L3", "cakgup3", "Eradikasi lanjutan, konfirmasi root cause, dan rekomendasi hardening pasca-insiden."),
        ],
        "activities": [
            ("cakgup1", "L1", "intake", "L1 menerima laporan user KPPN dan membuka case insiden malware endpoint."),
            ("cakgup1", "L1", "containment", "Perangkat diisolasi dari jaringan, user diminta berhenti menggunakan laptop, dan bukti awal diamankan."),
            ("cakgup2", "L2", "analysis", "L2 memeriksa hash, scheduled task, startup item, dan koneksi outbound untuk memastikan scope infeksi."),
            ("cakgup3", "L3", "eradication", "L3 menyiapkan eradikasi, validasi image forensik jika perlu, dan memastikan IOC diblok di perimeter."),
        ],
        "resolution_summary": (
            "Setelah eradikasi, perangkat di-reimage atau dibersihkan, password user di-reset, "
            "IOC diblok, dan user memperoleh edukasi singkat terkait sumber infeksi."
        ),
    },
    "phishing_kppn": {
        "title": "Insiden phishing pada salah satu KPPN",
        "organization_unit": "KPPN",
        "incident_type": "phishing-email",
        "priority": "critical",
        "source_channel": "user-report",
        "playbook": "SOC-PHISHING-EMAIL",
        "description": (
            "Terdapat laporan email phishing yang meniru komunikasi resmi dan meminta user "
            "membuka tautan atau mengisi kredensial. Case ini diproses sebagai insiden phishing "
            "dengan potensi credential harvesting."
        ),
        "tasks": [
            ("L1", "cakgup1", "Triage email phishing, kumpulkan header, URL, lampiran, dan identifikasi user terdampak."),
            ("L2", "cakgup2", "Analisis domain, URL, artefak email, dan verifikasi apakah ada user yang sudah klik atau submit kredensial."),
            ("L3", "cakgup3", "Koordinasi containment tenant/email gateway, threat hunting, dan rencana pemulihan akun jika compromise terkonfirmasi."),
        ],
        "activities": [
            ("cakgup1", "L1", "intake", "L1 menerima laporan phishing dari KPPN dan mengamankan sample email beserta header."),
            ("cakgup1", "L1", "containment", "Email serupa dicari di mailbox lain, URL diblok sementara, dan user diingatkan tidak klik tautan."),
            ("cakgup2", "L2", "analysis", "L2 menganalisis domain, reputasi URL, dan menilai kemungkinan credential harvesting."),
            ("cakgup3", "L3", "eradication", "L3 mengoordinasikan purge email, reset password terdampak, dan perbaikan aturan mail security."),
        ],
        "resolution_summary": (
            "Email di-purge dari mailbox terkait, URL dan domain diblok, password user terdampak di-reset, "
            "MFA diverifikasi, dan hunting lanjutan dilakukan untuk memastikan tidak ada lateral movement."
        ),
    },
}


SOC_SOP = [
    {
        "role": "SOC L1",
        "objective": "Validasi alert, intake laporan, triage awal, containment cepat, dan eskalasi terstruktur.",
        "steps": [
            "Terima alert atau laporan user, pastikan identitas pelapor, waktu kejadian, dan asset terdampak tercatat.",
            "Klasifikasikan insiden awal: malware, phishing, unauthorized access, web defacement, atau lainnya.",
            "Lakukan containment cepat yang aman: isolasi endpoint, suspend akun, blok IOC sementara, atau hold email.",
            "Buka ticket/case, isi kronologi singkat, owner awal, severity, dan evidence dasar.",
            "Eskalasi ke L2 jika indikasi insiden valid, berdampak, atau membutuhkan analisis teknis mendalam.",
        ],
    },
    {
        "role": "SOC L2",
        "objective": "Analisis teknis, scoping, korelasi IOC, dan rekomendasi containment/eradication yang lebih presisi.",
        "steps": [
            "Validasi artefak teknis seperti hash, process tree, registry, header email, URL, domain, dan log network.",
            "Tentukan scope dampak: user, host, mailbox, aplikasi, dan lokasi KPPN yang terdampak.",
            "Perbarui task dan timeline case dengan hasil analisis yang bisa dipakai auditor atau responder lain.",
            "Koordinasikan containment lanjutan: blok IOC permanen, disable akun, revoke token, atau quarantine file.",
            "Eskalasi ke L3 bila ditemukan persistence, privileged compromise, lateral movement, atau kebutuhan forensik lanjutan.",
        ],
    },
    {
        "role": "SOC L3",
        "objective": "Lead responder untuk eradikasi, forensik mendalam, recovery, dan penutupan kasus.",
        "steps": [
            "Tentukan strategi eradikasi: cleaning, reimage, credential reset massal, tenant purge, atau hardening kontrol.",
            "Lakukan analisis root cause dan pastikan tidak ada artefak persistence atau reinfection path yang tertinggal.",
            "Koordinasikan recovery dengan owner sistem atau KPPN terdampak agar layanan kembali normal secara aman.",
            "Susun resolution summary, lessons learned, dan rekomendasi pencegahan untuk siklus berikutnya.",
            "Tutup case setelah evidence, timeline, keputusan containment, dan hasil recovery terdokumentasi lengkap.",
        ],
    },
]


def playbook_choices() -> list[tuple[str, str]]:
    return [(key, value["title"]) for key, value in MANUAL_PLAYBOOKS.items()]


def classification_label_for_case(ticket_case) -> str:
    return IRIS_CASE_CLASSIFICATIONS.get(ticket_case.incident_type or "", "Other: Other")


def tags_for_case(ticket_case) -> list[str]:
    tags: list[str] = []
    if ticket_case.case_kind == "finding" and ticket_case.finding:
        tags.extend(
            [
                "satria",
                "scanner",
                ticket_case.finding.scanner.lower(),
                ticket_case.finding.severity_normalized.lower(),
            ]
        )
        if ticket_case.finding.cve:
            tags.append("cve")
    else:
        tags.extend(["satria", "manual"])

    if ticket_case.incident_type:
        tags.append(ticket_case.incident_type)
    if ticket_case.source_channel:
        tags.append(ticket_case.source_channel.replace("/", "-").replace(" ", "-").lower())
    if ticket_case.organization_unit:
        tags.append(ticket_case.organization_unit.replace(" ", "-").lower())

    deduped: list[str] = []
    seen: set[str] = set()
    for tag in tags:
        clean = tag.strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        deduped.append(clean)
    return deduped


def default_soc_id_for_case(ticket_case) -> str:
    prefix = "SATRIA-MANUAL" if ticket_case.case_kind == "manual" else "SATRIA-FINDING"
    return f"{prefix}-{ticket_case.id}"
