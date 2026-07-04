from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from dfir_iris_client.case import Case
from dfir_iris_client.customer import Customer
from dfir_iris_client.helper.case_classifications import CaseClassificationsHelper
from dfir_iris_client.session import ClientSession
from dfir_iris_client.users import User

from app.config import get_settings


@dataclass
class Incident:
    code: str
    title: str
    fields: dict[str, str]
    description: str
    iocs: list[tuple[str, str]]
    initial_actions: list[str]
    containment: list[str]
    eradication: list[str]
    recovery: list[str]
    lesson_learned: str


STAGE_PLAN = {
    1: {"phase": "monitoring", "owner_role": "L2", "close": False},
    2: {"phase": "analysis", "owner_role": "L2", "close": False},
    3: {"phase": "eradication", "owner_role": "L3", "close": False},
    4: {"phase": "stakeholder", "owner_role": "L3", "close": False},
    5: {"phase": "monitoring", "owner_role": "L2", "close": False},
    6: {"phase": "closed-impact", "owner_role": "L3", "close": True, "outcome": "True positive with impact"},
    7: {"phase": "containment", "owner_role": "L2", "close": False},
    8: {"phase": "developer-fix", "owner_role": "L3", "close": False},
    9: {"phase": "closed-legitimate", "owner_role": "L1", "close": True, "outcome": "Legitimate"},
    10: {"phase": "analysis", "owner_role": "L2", "close": False},
    11: {"phase": "closed-legitimate", "owner_role": "L1", "close": True, "outcome": "Legitimate"},
    12: {"phase": "closed-noimpact", "owner_role": "L2", "close": True, "outcome": "True positive without impact"},
    13: {"phase": "closed-false-positive", "owner_role": "L1", "close": True, "outcome": "False positive"},
    14: {"phase": "triage", "owner_role": "L1", "close": False},
    15: {"phase": "containment", "owner_role": "L2", "close": False},
    16: {"phase": "eradication", "owner_role": "L3", "close": False},
    17: {"phase": "critical-response", "owner_role": "L3", "close": False},
    18: {"phase": "closed-legitimate", "owner_role": "L1", "close": True, "outcome": "Legitimate"},
    19: {"phase": "analysis", "owner_role": "L2", "close": False},
    20: {"phase": "critical-dev-handoff", "owner_role": "L3", "close": False},
}

SPOTLIGHT_LABELS = {
    "INC-DUMMY-001": "BRUTE FORCE",
    "INC-DUMMY-002": "PHISHING",
    "INC-DUMMY-003": "MALWARE",
    "INC-DUMMY-008": "SQL INJECTION",
    "INC-DUMMY-009": "ACCESS ABUSE",
    "INC-DUMMY-010": "DATA EXFIL",
    "INC-DUMMY-013": "POLICY VIOLATION",
    "INC-DUMMY-016": "POWERSHELL",
    "INC-DUMMY-017": "WEBSHELL",
    "INC-DUMMY-020": "CREDENTIAL LEAK",
}

PHASE_LABEL = {
    "triage": "Triage awal SOC L1",
    "analysis": "Analisis teknis SOC L2",
    "containment": "Containment berjalan",
    "eradication": "Eradikasi teknis SOC L3",
    "monitoring": "Monitoring pasca-penanganan",
    "stakeholder": "Koordinasi stakeholder dan eskalasi teknis",
    "developer-fix": "Perbaikan oleh tim pengembang sedang berjalan",
    "critical-response": "Incident response kritikal aktif",
    "critical-dev-handoff": "Handoff kritikal ke pengembang dan pemilik sistem",
    "closed-impact": "Selesai dan ditutup dengan dampak terkonfirmasi",
    "closed-noimpact": "Selesai dan ditutup tanpa dampak material",
    "closed-false-positive": "Ditutup sebagai false positive",
    "closed-legitimate": "Ditutup sebagai aktivitas legitimate/policy review",
}

CLASSIFICATION_RULES = [
    (("phishing",), "fraud:phishing"),
    (("malware", "powershell", "webshell"), "malicious-code:trojan-malware"),
    (("sql injection",), "intrusion-attempts:exploit-known-vuln"),
    (("login gagal", "brute force", "suspicious login"), "intrusion-attempts:login-attempts"),
    (("port scanning", "reconnaissance", "scanner"), "information-gathering:scanner"),
    (("akses tidak sah", "unauthorized access"), "intrusion:privileged-account-compromise"),
    (("defacement", "web internal"), "intrusion:application-compromise"),
    (("download data", "kebocoran", "credential exposure", "repository"), "information-content-security:Unauthorised-information-access"),
    (("service penting berhenti", "availability", "outage"), "availability:outage"),
    (("ssl", "security configuration"), "vulnerable:vulnerable-service"),
    (("credential sharing", "policy violation"), "conformity:security-policy"),
]


def slugify(value: str) -> str:
    text = value.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-")


def parse_markdown(md_text: str) -> list[Incident]:
    text = md_text.replace("\r\n", "\n")
    pattern = re.compile(r"^##\s+(INC-DUMMY-\d+).*$", re.MULTILINE)
    matches = list(pattern.finditer(text))
    incidents: list[Incident] = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        block = text[start:end].strip()
        header_line = block.splitlines()[0]
        code = match.group(1)
        title = header_line.split(code, 1)[1].strip(" -–—â€”")
        fields = _parse_key_value_table(block)
        iocs = _parse_ioc_table(block)
        incidents.append(
            Incident(
                code=code,
                title=title,
                fields=fields,
                description=_section_text(block, "### Deskripsi"),
                iocs=iocs,
                initial_actions=_section_bullets(block, "### Initial Action"),
                containment=_section_bullets(block, "### Containment"),
                eradication=_section_bullets(block, "### Eradication"),
                recovery=_section_bullets(block, "### Recovery"),
                lesson_learned=_section_text(block, "### Lesson Learned"),
            )
        )
    return incidents


def _parse_key_value_table(block: str) -> dict[str, str]:
    rows: dict[str, str] = {}
    table_match = re.search(r"\| Field \|.*?\n((?:\|.*\n)+)", block)
    if not table_match:
        return rows
    for raw in table_match.group(1).splitlines():
        if raw.startswith("|---"):
            continue
        parts = [part.strip() for part in raw.strip().strip("|").split("|")]
        if len(parts) >= 2 and parts[0] and parts[0] != "Field":
            rows[parts[0]] = parts[1]
    return rows


def _parse_ioc_table(block: str) -> list[tuple[str, str]]:
    match = re.search(r"### Indicator of Compromise\s*\n\s*\|.*?\n((?:\|.*\n)+)", block)
    values: list[tuple[str, str]] = []
    if not match:
        return values
    for raw in match.group(1).splitlines():
        if raw.startswith("|---"):
            continue
        parts = [part.strip() for part in raw.strip().strip("|").split("|")]
        if len(parts) >= 2 and parts[0] and parts[0] != "Jenis IoC":
            values.append((parts[0], parts[1]))
    return values


def _section_text(block: str, header: str) -> str:
    start = block.find(header)
    if start == -1:
        return ""
    remainder = block[start + len(header):].lstrip()
    next_match = re.search(r"\n###\s+", remainder)
    content = remainder[:next_match.start()] if next_match else remainder
    return content.strip()


def _section_bullets(block: str, header: str) -> list[str]:
    text = _section_text(block, header)
    lines = []
    for line in text.splitlines():
        cleaned = line.strip()
        if cleaned.startswith("- "):
            lines.append(cleaned[2:].strip())
    return lines


def classification_for_incident(helper: CaseClassificationsHelper, incident: Incident):
    haystack = f"{incident.title} {incident.fields.get('Category', '')}".lower()
    for keywords, classification in CLASSIFICATION_RULES:
        if any(keyword in haystack for keyword in keywords):
            resolved = helper.lookup_case_classification_name(classification)
            if resolved:
                return resolved
    return helper.lookup_case_classification_name("other:other") or 36


def display_case_title(incident: Incident) -> str:
    spotlight = SPOTLIGHT_LABELS.get(incident.code)
    if spotlight:
        return f"[{spotlight}] {incident.title}"
    return incident.title


def phase_for_incident(incident: Incident) -> dict[str, str | bool]:
    number = int(incident.code.split("-")[-1])
    return STAGE_PLAN.get(number, {"phase": "analysis", "owner_role": "L2", "close": False})


def infer_ioc_type(label: str, value: str) -> str | None:
    normalized = label.lower()
    value_lower = value.lower()
    if "source ip" in normalized or "login ip" in normalized:
        return "ip-src"
    if "destination ip" in normalized:
        return "ip-dst"
    if "source host" in normalized or "destination host" in normalized or "hostname" in normalized:
        return "hostname"
    if "username" in normalized or "user id" in normalized or "author" in normalized:
        return "account"
    if "sender email" in normalized:
        return "email-src"
    if "recipient" in normalized:
        return "email-dst"
    if "subject" in normalized:
        return "email-subject"
    if "url" in normalized:
        return "url"
    if "endpoint" in normalized or "related url" in normalized:
        return "uri"
    if "domain" in normalized:
        return "domain"
    if "file hash" in normalized or "hash sha256" in normalized:
        return "sha256"
    if "file name" in normalized or "filename" in normalized or "file " in normalized:
        return "filename"
    if "user agent" in normalized:
        return "user-agent"
    if "port" in normalized:
        return "port"
    if "serial" in normalized:
        return "text"
    if "repository" in normalized or "commit id" in normalized:
        return "text"
    if "email" in normalized:
        return "email"
    if "source ip" not in normalized and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$", value):
        return "ip-any"
    if "http://" in value_lower or "https://" in value_lower or "hxxp" in value_lower:
        return "url"
    return None


def asset_blueprint(incident: Incident, severity: str) -> list[dict[str, str]]:
    affected = incident.fields.get("Affected Asset", "")
    reporter = incident.fields.get("Reporter", "")
    normalized = affected.lower()
    assets: list[dict[str, str]] = []

    if any(term in normalized for term in ["laptop", "endpoint"]):
        assets.append({"name": affected, "type": "Windows - Computer"})
    elif "vpn" in normalized:
        assets.append({"name": affected, "type": "VPN"})
    elif "web" in normalized:
        assets.append({"name": affected, "type": "Linux - Server"})
    elif "server" in normalized:
        assets.append({"name": affected, "type": "Linux - Server"})
    elif "akun" in normalized or "email" in normalized:
        assets.append({"name": affected, "type": "Account"})
    elif "api" in normalized or "portal" in normalized or "aplikasi" in normalized:
        assets.append({"name": affected, "type": "Linux - Server"})
    else:
        assets.append({"name": affected or incident.title, "type": "Account"})

    for label, value in incident.iocs:
        lowered = label.lower()
        if "username" in lowered or "recipient" in lowered or "sender email" in lowered:
            assets.append({"name": value, "type": "Account"})
            break

    if severity in {"High", "Critical"}:
        assets.append({"name": f"Koordinasi {incident.fields.get('Source', 'Monitoring')}", "type": "Firewall"})

    deduped = []
    seen = set()
    for asset in assets:
        key = (asset["name"], asset["type"])
        if key in seen or not asset["name"]:
            continue
        seen.add(key)
        deduped.append(asset)
    return deduped[:3]


def compromise_status_for_phase(phase: str) -> str:
    if phase.startswith("closed-legitimate") or phase.startswith("closed-false-positive"):
        return "Not compromised"
    if phase in {"triage", "analysis"}:
        return "To be determined"
    return "Compromised"


def analysis_status_for_phase(phase: str) -> str:
    if phase.startswith("closed"):
        return "Done"
    return {
        "triage": "To be done",
        "analysis": "Started",
        "containment": "Started",
        "eradication": "Started",
        "monitoring": "Pending",
        "stakeholder": "Started",
        "developer-fix": "Pending",
        "critical-response": "Started",
        "critical-dev-handoff": "Pending",
    }.get(phase, "Started")


def task_statuses_for_phase(phase: str) -> list[str]:
    mapping = {
        "triage": ["In progress", "To do", "To do", "To do", "To do"],
        "analysis": ["Done", "In progress", "To do", "To do", "To do"],
        "containment": ["Done", "Done", "In progress", "To do", "To do"],
        "eradication": ["Done", "Done", "In progress", "In progress", "To do"],
        "stakeholder": ["Done", "Done", "In progress", "In progress", "To do"],
        "developer-fix": ["Done", "Done", "In progress", "In progress", "To do"],
        "critical-response": ["Done", "In progress", "In progress", "To do", "To do"],
        "critical-dev-handoff": ["Done", "Done", "In progress", "In progress", "To do"],
        "monitoring": ["Done", "Done", "Done", "In progress", "To do"],
    }
    if phase.startswith("closed"):
        return ["Done", "Done", "Done", "Done", "Done"]
    return mapping.get(phase, ["Done", "In progress", "To do", "To do", "To do"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed IRIS with rich dummy cases from markdown scenarios.")
    parser.add_argument("markdown_path", type=Path)
    parser.add_argument("--customer-name", default="DJPb - Simulasi IRIS Top Management")
    parser.add_argument("--cleanup-prefix", default="INC-DUMMY-")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    markdown_text = args.markdown_path.read_text(encoding="utf-8")
    incidents = parse_markdown(markdown_text)
    if not incidents:
        raise SystemExit("No incident sections found in markdown file.")
    if args.limit > 0:
        incidents = incidents[:args.limit]

    settings = get_settings()
    session = ClientSession(
        apikey=settings.iris_api_key,
        host=settings.iris_url,
        ssl_verify=settings.iris_verify_ssl,
        agent="SATRIA-IRIS-DEMO",
    )
    case_api = Case(session)
    customer_api = Customer(session)
    user_api = User(session)
    classification_helper = CaseClassificationsHelper(session)

    user_map = resolve_users(user_api)
    customer_value = resolve_customer_id(customer_api, args.customer_name)

    cleanup_existing_dummy_cases(case_api, args.cleanup_prefix)

    created = 0
    for incident in incidents:
        phase_meta = phase_for_incident(incident)
        phase = str(phase_meta["phase"])
        severity = incident.fields.get("Severity", "Medium")
        case_classification = classification_for_incident(classification_helper, incident)
        owner_role = str(phase_meta["owner_role"])
        owner_id = user_map.get(owner_role)
        case_tags = build_case_tags(incident, phase)
        current_label = PHASE_LABEL.get(phase, phase.title())

        create_customer = False
        case_customer = customer_value if customer_value else args.customer_name
        if not customer_value and created == 0:
            create_customer = True

        add_case_resp = case_api.add_case(
            case_name=f"{incident.code} | {display_case_title(incident)}",
            case_description=build_case_description(incident, current_label),
            case_customer=case_customer,
            case_classification=case_classification,
            soc_id=incident.code,
            create_customer=create_customer,
        )
        case_id = extract_response_value(add_case_resp, "case_id")
        if not case_id:
            raise RuntimeError(f"Unable to create case for {incident.code}: {add_case_resp.get_data()}")
        case_id = int(case_id)

        if create_customer:
            customer_value = resolve_customer_id(customer_api, args.customer_name) or customer_value

        case_handle = Case(session, case_id=case_id)
        case_handle.update_case(
            case_id=case_id,
            case_name=f"{incident.code} | {display_case_title(incident)}",
            case_description=build_case_description(incident, current_label),
            case_classification=case_classification,
            case_owner=owner_id,
            soc_id=incident.code,
            case_tags=case_tags,
        )

        executive_dir = ensure_notes_directory(case_handle, case_id, "Executive Brief")
        timeline_dir = ensure_notes_directory(case_handle, case_id, "Timeline & Triage")
        technical_dir = ensure_notes_directory(case_handle, case_id, "Technical Analysis")
        stakeholder_dir = ensure_notes_directory(case_handle, case_id, "Stakeholder Coordination")

        add_note_with_comment(
            case_handle,
            case_id,
            executive_dir,
            "Ringkasan untuk pimpinan",
            build_executive_note(incident, phase, owner_role),
            "Catatan ini disiapkan untuk membantu pimpinan memahami posisi kasus saat ini.",
        )
        add_note_with_comment(
            case_handle,
            case_id,
            timeline_dir,
            "Timeline operasional insiden",
            build_timeline_note(incident),
            "Timeline ini dipakai L1-L3 sebagai acuan kronologis dan bukti tindak lanjut.",
        )
        add_note_with_comment(
            case_handle,
            case_id,
            technical_dir,
            "Analisis teknis dan hipotesis",
            build_technical_note(incident),
            "Analisis teknis diperbarui bertahap sesuai temuan IOC dan validasi evidence.",
        )
        add_note_with_comment(
            case_handle,
            case_id,
            stakeholder_dir,
            "Koordinasi pengembang dan stakeholder",
            build_stakeholder_note(incident, phase),
            "Catatan ini menunjukkan jalur koordinasi dari SOC menuju pengembang, owner sistem, dan pimpinan terkait.",
        )

        ioc_ids = []
        for label, value in incident.iocs:
            ioc_type = infer_ioc_type(label, value)
            if not ioc_type:
                continue
            try:
                ioc_resp = case_handle.add_ioc(
                    value=value,
                    ioc_type=ioc_type,
                    description=f"{label} pada {incident.code}",
                    ioc_tlp="amber",
                    ioc_tags=["dummy", slugify(incident.code), slugify(severity)],
                    cid=case_id,
                )
                ioc_id = extract_response_value(ioc_resp, "ioc_id") or extract_response_value(ioc_resp, "id")
                if ioc_id:
                    ioc_ids.append(int(ioc_id))
                    case_handle.add_ioc_comment(int(ioc_id), f"IOC `{label}` dipakai untuk simulasi enrichment dan korelasi pada {incident.code}.", cid=case_id)
            except Exception as exc:  # noqa: BLE001
                print(f"[warn] IOC skipped for {incident.code} / {label}: {exc}")

        for asset in asset_blueprint(incident, severity):
            try:
                asset_resp = case_handle.add_asset(
                    name=asset["name"],
                    asset_type=asset["type"],
                    analysis_status=analysis_status_for_phase(phase),
                    compromise_status=compromise_status_for_phase(phase),
                    tags=case_tags[:5],
                    description=f"Asset simulasi untuk {incident.code} - {incident.fields.get('Category', incident.title)}",
                    additional_info=f"Reporter: {incident.fields.get('Reporter', '-')}\nSumber: {incident.fields.get('Source', '-')}\nSeverity: {severity}",
                    ioc_links=ioc_ids[:3] or None,
                    cid=case_id,
                )
                asset_id = extract_response_value(asset_resp, "asset_id") or extract_response_value(asset_resp, "id")
                if asset_id:
                    case_handle.add_asset_comment(int(asset_id), f"Asset ini ditandai dalam skenario {incident.code} untuk menggambarkan cakupan insiden dan koordinasi pemilik sistem.", cid=case_id)
            except Exception as exc:  # noqa: BLE001
                print(f"[warn] Asset skipped for {incident.code} / {asset['name']}: {exc}")

        task_owner_ids = [user_map["L1"], user_map["L2"], user_map["L3"], user_map["L3"], user_map["L2"]]
        task_titles = [
            "Triage awal dan validasi alert",
            "Analisis teknis dan korelasi IOC",
            "Containment, eradikasi, dan hardening",
            "Koordinasi pengembang / owner sistem",
            "Pelaporan stakeholder dan closure pack",
        ]
        task_descriptions = build_task_descriptions(incident)
        task_statuses = task_statuses_for_phase(phase)
        for title, description, task_status, assignee in zip(task_titles, task_descriptions, task_statuses, task_owner_ids, strict=True):
            task_resp = case_handle.add_task(
                title=title,
                status=task_status,
                assignees=[assignee],
                description=description,
                tags=[slugify(incident.code), slugify(phase), slugify(severity)],
                cid=case_id,
            )
            task_id = extract_response_value(task_resp, "task_id") or extract_response_value(task_resp, "id")
            if task_id:
                case_handle.add_task_comment(int(task_id), f"Tugas `{title}` diisikan sebagai bagian dari simulasi alur SOC end-to-end untuk {incident.code}.", cid=case_id)

        for log_line in build_task_logs(incident, phase, owner_role):
            case_handle.add_task_log(message=log_line, cid=case_id)

        evidence_folder_id = ensure_evidence_folder(case_handle, case_id, incident.code)
        for evidence in build_evidence_payloads(incident, phase):
            content = evidence["content"].encode("utf-8")
            sha256 = hashlib.sha256(content).hexdigest()
            evidence_resp = case_handle.add_evidence(
                filename=evidence["filename"],
                file_size=len(content),
                description=evidence["description"],
                file_hash=sha256,
                cid=case_id,
            )
            evidence_id = extract_response_value(evidence_resp, "evidence_id") or extract_response_value(evidence_resp, "id")
            if evidence_id:
                case_handle.add_evidence_comment(int(evidence_id), f"Evidence `{evidence['filename']}` disiapkan untuk memperlihatkan contoh artefak investigasi pada IRIS.", cid=case_id)
            case_handle.add_ds_file(
                parent_id=evidence_folder_id,
                file_stream=io.BytesIO(content),
                filename=evidence["filename"],
                file_description=evidence["description"],
                file_is_evidence=True,
                file_tags=["dummy", slugify(incident.code), slugify(phase)],
                cid=case_id,
            )

        case_handle.set_summary(build_case_summary(incident, phase, owner_role), cid=case_id)

        if phase_meta.get("close"):
            case_handle.set_case_outcome_status(phase_meta.get("outcome", "Unknown"), case_id=case_id)
            case_handle.close_case(case_id=case_id)
        else:
            case_handle.reopen_case(case_id=case_id)

        created += 1
        print(f"[ok] seeded {incident.code} -> case_id={case_id}")

    print(json.dumps({"seeded_cases": created, "customer_name": args.customer_name}, ensure_ascii=False))


def resolve_users(user_api: User) -> dict[str, int]:
    users = user_api.list_users().get_data() or []
    mapping: dict[str, int] = {}
    for user in users:
        login = str(user.get("user_login", "")).lower()
        name = str(user.get("user_name", "")).lower()
        if "l1" in login or "l1" in name:
            mapping["L1"] = int(user["user_id"])
        elif "l2" in login or "l2" in name:
            mapping["L2"] = int(user["user_id"])
        elif "l3" in login or "l3" in name:
            mapping["L3"] = int(user["user_id"])
    if {"L1", "L2", "L3"} - set(mapping):
        raise RuntimeError(f"Unable to map SOC users from IRIS users list: {users}")
    return mapping


def resolve_customer_id(customer_api: Customer, customer_name: str) -> int | None:
    response = customer_api.lookup_customer(customer_name)
    try:
        customer_id = response.get_data_field("customer_id")
        if customer_id not in (None, "", []):
            return int(customer_id)
    except Exception:  # noqa: BLE001
        pass

    data = response.get_data()
    if isinstance(data, dict):
        direct_id = data.get("customer_id") or data.get("id")
        if direct_id not in (None, "", []):
            return int(direct_id)

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                item_name = str(item.get("customer_name") or item.get("name") or "").strip().lower()
                if item_name == customer_name.strip().lower():
                    direct_id = item.get("customer_id") or item.get("id")
                    if direct_id not in (None, "", []):
                        return int(direct_id)
        return None

    return None


def cleanup_existing_dummy_cases(case_api: Case, prefix: str) -> None:
    cases = case_api.list_cases().get_data() or []
    for case in cases:
        soc_id = str(case.get("case_soc_id") or "")
        if soc_id.startswith(prefix):
            case_api.delete_case(cid=int(case["case_id"]))
            print(f"[cleanup] deleted existing case {case['case_id']} ({soc_id})")


def build_case_tags(incident: Incident, phase: str) -> list[str]:
    severity = incident.fields.get("Severity", "Medium")
    category = incident.fields.get("Category", incident.title)
    source = incident.fields.get("Source", "unknown")
    tags = [
        "dummy",
        "dfir-iris",
        "djpb",
        "top-management",
        slugify(incident.code),
        f"severity-{slugify(severity)}",
        f"phase-{slugify(phase)}",
        f"category-{slugify(category)}",
        f"source-{slugify(source)}",
    ]
    spotlight = SPOTLIGHT_LABELS.get(incident.code)
    if spotlight:
        tags.append(f"spotlight-{slugify(spotlight)}")
    return tags


def build_case_description(incident: Incident, current_label: str) -> str:
    return (
        f"{incident.description}\n\n"
        f"Severity: {incident.fields.get('Severity', '-')}\n"
        f"Kategori: {incident.fields.get('Category', '-')}\n"
        f"Sumber laporan: {incident.fields.get('Source', '-')}\n"
        f"Aset terdampak: {incident.fields.get('Affected Asset', '-')}\n"
        f"Reporter: {incident.fields.get('Reporter', '-')}\n"
        f"Tahap simulasi saat ini: {current_label}\n"
        f"Deteksi awal: {incident.fields.get('Detection Time', '-')}"
    )


def build_case_summary(incident: Incident, phase: str, owner_role: str) -> str:
    severity = incident.fields.get("Severity", "Medium")
    return (
        f"## Executive Summary\n"
        f"- Kode insiden: {incident.code}\n"
        f"- Severity: {severity}\n"
        f"- Tahap simulasi saat ini: {PHASE_LABEL.get(phase, phase)}\n"
        f"- PIC aktif: SOC {owner_role}\n"
        f"- Aset terdampak: {incident.fields.get('Affected Asset', '-')}\n\n"
        f"## Ringkasan Temuan\n"
        f"{incident.description}\n\n"
        f"## Langkah Saat Ini\n"
        f"- Validasi dan triase awal telah dijalankan.\n"
        f"- Jalur koordinasi ke L2, L3, pengembang, dan stakeholder diisi untuk simulasi penuh IRIS.\n"
        f"- Case ini dipakai sebagai dummy flow untuk memahami fungsionalitas DFIR-IRIS dari hulu ke hilir.\n\n"
        f"## Lesson Learned\n"
        f"{incident.lesson_learned}"
    )


def build_executive_note(incident: Incident, phase: str, owner_role: str) -> str:
    return (
        f"# Executive Brief\n\n"
        f"- **Incident Code:** {incident.code}\n"
        f"- **Incident Title:** {incident.title}\n"
        f"- **Severity:** {incident.fields.get('Severity', '-')}\n"
        f"- **Current Phase:** {PHASE_LABEL.get(phase, phase)}\n"
        f"- **Active Owner:** SOC {owner_role}\n"
        f"- **Business Context:** {incident.fields.get('Affected Asset', '-')}\n"
        f"- **Stakeholder Update:** Case ini disusun untuk menunjukkan bagaimana IRIS menampung intake, analisis, koordinasi, evidence, dan penutupan kasus secara terstruktur.\n\n"
        f"## Management Focus\n"
        f"Top management dapat melihat bahwa satu case di IRIS memuat kronologi, tugas multi-level, evidence, IOC, dan jalur koordinasi lintas fungsi dalam satu tempat."
    )


def build_timeline_note(incident: Incident) -> str:
    bullets = [
        f"- Detection Time: {incident.fields.get('Detection Time', '-')}",
        f"- Source: {incident.fields.get('Source', '-')}",
        f"- Reporter: {incident.fields.get('Reporter', '-')}",
        f"- Initial validation: {incident.initial_actions[0] if incident.initial_actions else 'Validasi awal dilakukan oleh SOC L1.'}",
        f"- Containment direction: {incident.containment[0] if incident.containment else 'Containment akan mengikuti hasil validasi IOC.'}",
        f"- Recovery target: {incident.recovery[0] if incident.recovery else 'Recovery dilaksanakan setelah eradikasi tervalidasi.'}",
    ]
    return "# Timeline & Triage\n\n" + "\n".join(bullets)


def build_technical_note(incident: Incident) -> str:
    ioc_lines = "\n".join(f"- **{label}:** `{value}`" for label, value in incident.iocs[:8]) or "- IOC akan diisi setelah validasi."
    return (
        "# Technical Analysis\n\n"
        f"## Deskripsi\n{incident.description}\n\n"
        "## IOC Prioritas\n"
        f"{ioc_lines}\n\n"
        "## Hipotesis Investigasi\n"
        f"- {incident.initial_actions[0] if incident.initial_actions else 'Korelasi log dimulai dari sumber alert.'}\n"
        f"- {incident.eradication[0] if incident.eradication else 'Tim teknis menyiapkan jalur eradikasi sesuai dampak.'}\n"
        f"- {incident.lesson_learned}"
    )


def build_stakeholder_note(incident: Incident, phase: str) -> str:
    stakeholder_text = {
        "developer-fix": "Perbaikan sementara sedang dikembangkan oleh tim aplikasi/pengembang dengan pendampingan SOC L3.",
        "critical-dev-handoff": "Case kritikal sudah dibawa ke jalur koordinasi pengembang, infrastruktur, dan pimpinan layanan untuk percepatan remediasi.",
        "stakeholder": "Update berkala diberikan kepada pemilik layanan, helpdesk, dan unit kerja terdampak.",
    }.get(phase, "Koordinasi lintas tim disiapkan agar bukti, keputusan containment, dan rencana pemulihan tetap sinkron.")
    return (
        "# Stakeholder Coordination\n\n"
        f"- **Unit terdampak:** {incident.fields.get('Affected Asset', '-')}\n"
        f"- **Reporter awal:** {incident.fields.get('Reporter', '-')}\n"
        f"- **Narahubung teknis:** SOC L1 -> SOC L2 -> SOC L3\n"
        f"- **Koordinasi lanjutan:** {stakeholder_text}\n\n"
        "## Aksi Stakeholder\n"
        "- Tim pengembang menilai perubahan kode atau konfigurasi yang diperlukan.\n"
        "- Tim infrastruktur memvalidasi dampak terhadap layanan dan akses.\n"
        "- Pimpinan menerima ringkasan status, dampak, dan kebutuhan keputusan jika eskalasi dibutuhkan."
    )


def build_task_descriptions(incident: Incident) -> list[str]:
    return [
        f"L1 melakukan intake, validasi awal, dan penetapan severity untuk {incident.code}. Fokus: {incident.initial_actions[0] if incident.initial_actions else 'validasi alert dan konteks pelapor.'}",
        f"L2 melakukan analisis teknis, enrichment IOC, dan scoping. Fokus: {incident.initial_actions[1] if len(incident.initial_actions) > 1 else incident.description}",
        f"L3 mengeksekusi containment/eradikasi dan memastikan tidak ada persistence. Fokus: {incident.eradication[0] if incident.eradication else 'hardening dan pemulihan teknis.'}",
        f"Koordinasi owner sistem, pengembang, atau pengelola layanan. Fokus: {incident.containment[0] if incident.containment else 'sinkronisasi tindakan pemulihan dengan pemilik aset.'}",
        f"Siapkan closure pack, lessons learned, dan bahan paparan ke stakeholder. Fokus: {incident.lesson_learned}",
    ]


def build_task_logs(incident: Incident, phase: str, owner_role: str) -> Iterable[str]:
    lines = [
        f"[L1] Intake diterima dari {incident.fields.get('Source', '-')} pada {incident.fields.get('Detection Time', '-')}.",
        f"[L1] Validasi awal: {incident.initial_actions[0] if incident.initial_actions else 'SOC memastikan alert dan aset terdampak valid.'}",
        f"[L2] Korelasi IOC dan scoping: {incident.initial_actions[1] if len(incident.initial_actions) > 1 else incident.description}",
        f"[L3] Arah eradikasi: {incident.eradication[0] if incident.eradication else 'Tim menyiapkan eradikasi dan hardening.'}",
        f"[Stakeholder] {stakeholder_update_line(phase)}",
        f"[Owner] Case saat ini berada pada fase `{PHASE_LABEL.get(phase, phase)}` dengan owner aktif SOC {owner_role}.",
    ]
    if phase.startswith("closed"):
        lines.append(f"[Closure] Case ditutup dengan lesson learned: {incident.lesson_learned}")
    return lines


def build_evidence_payloads(incident: Incident, phase: str) -> list[dict[str, str]]:
    ioc_json = json.dumps(
        {
            "incident_code": incident.code,
            "severity": incident.fields.get("Severity", "-"),
            "phase": phase,
            "iocs": [{"label": label, "value": value} for label, value in incident.iocs],
        },
        indent=2,
        ensure_ascii=False,
    )
    timeline = "\n".join(build_task_logs(incident, phase, STAGE_PLAN.get(int(incident.code.split('-')[-1]), {}).get("owner_role", "L2")))
    executive = build_case_summary(incident, phase, STAGE_PLAN.get(int(incident.code.split('-')[-1]), {}).get("owner_role", "L2"))
    return [
        {
            "filename": f"{incident.code.lower()}-executive-brief.md",
            "description": "Executive brief dummy untuk top management.",
            "content": executive,
        },
        {
            "filename": f"{incident.code.lower()}-ioc-enrichment.json",
            "description": "Contoh artefak hasil enrichment IOC dan korelasi awal.",
            "content": ioc_json,
        },
        {
            "filename": f"{incident.code.lower()}-timeline.txt",
            "description": "Timeline dummy penanganan dari L1 sampai stakeholder.",
            "content": timeline,
        },
    ]


def stakeholder_update_line(phase: str) -> str:
    return {
        "developer-fix": "Tim pengembang telah menerima handoff perbaikan dan menyiapkan perubahan aplikasi secara terkontrol.",
        "critical-dev-handoff": "Koordinasi kritikal berjalan dengan pengembang, infrastruktur, dan pemilik layanan untuk percepatan pemulihan.",
        "stakeholder": "Pemilik layanan, helpdesk, dan unit kerja terdampak menerima update berkala dari SOC.",
    }.get(phase, "Koordinasi lintas tim disiapkan agar tindakan containment, recovery, dan komunikasi tetap sinkron.")


def ensure_notes_directory(case_handle: Case, case_id: int, name: str) -> int:
    directories = case_handle.list_notes_directories(cid=case_id).get_data() or []
    for entry in directories:
        if entry.get("name") == name:
            return int(entry["id"])
    created = case_handle.add_notes_directory(name, cid=case_id)
    directory_id = extract_response_value(created, "id") or extract_response_value(created, "directory_id")
    if not directory_id:
        raise RuntimeError(f"Unable to create note directory {name} for case {case_id}")
    return int(directory_id)


def ensure_evidence_folder(case_handle: Case, case_id: int, folder_name: str) -> int:
    tree = case_handle.list_ds_tree(cid=case_id).get_data()
    root_id = find_tree_node_id(tree, "Evidences")
    if root_id is None:
        case_handle.add_ds_folder(parent_id=0, folder_name="Evidences", cid=case_id)
        tree = case_handle.list_ds_tree(cid=case_id).get_data()
        root_id = find_tree_node_id(tree, "Evidences")
    if root_id is None:
        raise RuntimeError(f"Unable to resolve Evidences root folder for case {case_id}")
    child_id = find_tree_node_id(tree, folder_name) if tree else None
    if child_id is not None:
        return int(child_id)
    case_handle.add_ds_folder(parent_id=int(root_id), folder_name=folder_name, cid=case_id)
    refreshed_tree = case_handle.list_ds_tree(cid=case_id).get_data()
    folder_id = find_tree_node_id(refreshed_tree, folder_name)
    if not folder_id:
        raise RuntimeError(f"Unable to create evidence folder {folder_name} for case {case_id}")
    return int(folder_id)


def add_note_with_comment(case_handle: Case, case_id: int, directory_id: int, title: str, content: str, comment: str) -> None:
    note_resp = case_handle.add_note(note_title=title, note_content=content, directory_id=directory_id, cid=case_id)
    note_id = extract_response_value(note_resp, "note_id") or extract_response_value(note_resp, "id")
    if note_id:
        case_handle.add_note_comment(int(note_id), comment, cid=case_id)


def extract_response_value(response, key: str):
    try:
        value = response.get_data_field(key)
        if value not in (None, "", []):
            return value
    except Exception:  # noqa: BLE001
        pass
    data = response.get_data()
    if isinstance(data, dict):
        if key in data:
            return data.get(key)
        for nested_key in ("case", "task", "evidence", "ioc", "note", "folder", "directory"):
            nested = data.get(nested_key)
            if isinstance(nested, dict) and key in nested:
                return nested.get(key)
    return None


def find_tree_node_id(tree, wanted_name: str):
    if isinstance(tree, dict):
        for node_id, node in tree.items():
            if isinstance(node, dict):
                if node.get("name") == wanted_name:
                    return str(node_id).split("-", 1)[-1]
                found = find_tree_node_id(node.get("children"), wanted_name)
                if found is not None:
                    return found
    elif isinstance(tree, list):
        for node in tree:
            if isinstance(node, dict):
                if node.get("name") == wanted_name:
                    return node.get("id")
                found = find_tree_node_id(node.get("children"), wanted_name)
                if found is not None:
                    return found
    return None


if __name__ == "__main__":
    main()
