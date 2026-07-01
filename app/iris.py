from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from .config import get_settings
from .models import Asset, Finding, TicketActivity, TicketCase, TicketEvidence, TicketTask
from .soc import default_soc_id_for_case, tags_for_case
from .ticketing import create_ticket_for_finding

settings = get_settings()

try:
    from dfir_iris_client.alert import Alert
    from dfir_iris_client.case import Case
    from dfir_iris_client.customer import Customer
    from dfir_iris_client.helper.case_classifications import CaseClassificationsHelper
    from dfir_iris_client.session import ClientSession
    from dfir_iris_client.users import User
except Exception:  # pragma: no cover - optional runtime dependency
    Alert = Case = Customer = CaseClassificationsHelper = ClientSession = User = None


def send_finding_to_iris(db: Session, finding: Finding, asset: Asset) -> str:
    sync_mode = "api" if _can_use_iris_api() else "stub"
    case = create_ticket_for_finding(db, finding, asset, sync_mode=sync_mode)
    sync_ticket_case(db, case)
    finding.iris_alert_id = case.remote_case_id or case.remote_alert_id
    return case.remote_case_id or case.remote_alert_id or f"IRIS-LOCAL-{finding.id}"


def list_remote_cases() -> list[dict]:
    if not _can_use_iris_api():
        return []
    try:
        session = _client_session()
        case_client = Case(session)
        response = case_client.list_cases()
        data = response.get_data()
        return data if isinstance(data, list) else []
    except Exception:
        return []


def find_remote_cases_by_soc_id(soc_id: str | None) -> list[dict]:
    if not soc_id:
        return []
    matches = [item for item in list_remote_cases() if item.get("case_soc_id") == soc_id]
    return sorted(matches, key=lambda item: int(item.get("case_id") or 0), reverse=True)


def find_remote_case_by_soc_id(soc_id: str | None) -> dict | None:
    matches = find_remote_cases_by_soc_id(soc_id)
    return matches[0] if matches else None


def get_remote_case_bundle(ticket_case: TicketCase) -> dict | None:
    if not _can_use_iris_api():
        return None
    remote_case_id = _as_int(ticket_case.remote_case_id)
    if not remote_case_id:
        matched = find_remote_case_by_soc_id(ticket_case.remote_case_soc_id or default_soc_id_for_case(ticket_case))
        if matched:
            ticket_case.remote_case_id = str(matched.get("case_id") or "")
            ticket_case.remote_case_name = matched.get("case_name") or ticket_case.remote_case_name
            remote_case_id = _as_int(ticket_case.remote_case_id)
    if not remote_case_id:
        return None

    try:
        session = _client_session()
        case_client = Case(session, case_id=remote_case_id)
        summary = case_client.get_case(remote_case_id).get_data() or {}
        tasks_payload = case_client.list_tasks(remote_case_id).get_data() or {}
        evidences_payload = case_client.list_evidences(remote_case_id).get_data() or {}
        note_dirs_payload = case_client.list_notes_directories(remote_case_id).get_data() or []
    except Exception:
        return None

    return {
        "summary": summary,
        "tasks": tasks_payload.get("tasks", []) if isinstance(tasks_payload, dict) else [],
        "task_status_catalog": tasks_payload.get("tasks_status", []) if isinstance(tasks_payload, dict) else [],
        "evidences": evidences_payload.get("evidences", []) if isinstance(evidences_payload, dict) else [],
        "note_directories": note_dirs_payload if isinstance(note_dirs_payload, list) else [],
    }


def refresh_ticket_case_from_iris(ticket_case: TicketCase) -> TicketCase:
    if not ticket_case.remote_case_id:
        matched = find_remote_case_by_soc_id(ticket_case.remote_case_soc_id or default_soc_id_for_case(ticket_case))
        if matched:
            ticket_case.remote_case_id = str(matched.get("case_id") or "")
            ticket_case.remote_case_name = matched.get("case_name") or ticket_case.remote_case_name
    bundle = get_remote_case_bundle(ticket_case)
    if not bundle:
        ticket_case.last_sync_status = "monitor-unavailable"
        return ticket_case

    summary = bundle["summary"]
    ticket_case.remote_case_name = summary.get("case_name") or ticket_case.remote_case_name or ticket_case.title
    ticket_case.remote_case_soc_id = summary.get("case_soc_id") or ticket_case.remote_case_soc_id
    ticket_case.remote_customer_id = str(summary.get("customer_id") or ticket_case.remote_customer_id or "")
    ticket_case.current_owner = summary.get("owner") or ticket_case.current_owner
    ticket_case.last_sync_status = "monitored"
    ticket_case.last_sync_error = None
    return ticket_case


def sync_ticket_case_status(
    ticket_case: TicketCase,
    previous_status: str | None = None,
    activity: TicketActivity | None = None,
) -> TicketCase:
    if not _can_use_iris_api():
        ticket_case.last_sync_status = "local-only"
        ticket_case.last_sync_error = None
        return ticket_case

    remote_case_id = _as_int(ticket_case.remote_case_id)
    if not remote_case_id:
        matched = find_remote_case_by_soc_id(ticket_case.remote_case_soc_id or default_soc_id_for_case(ticket_case))
        if matched:
            ticket_case.remote_case_id = str(matched.get("case_id") or "")
            ticket_case.remote_case_name = matched.get("case_name") or ticket_case.remote_case_name
            remote_case_id = _as_int(ticket_case.remote_case_id)

    if not remote_case_id:
        ticket_case.last_sync_status = "remote-missing"
        ticket_case.last_sync_error = "remote case not found"
        return ticket_case

    try:
        session = _client_session()
        case_client = Case(session, case_id=remote_case_id)
        status_changed = bool(previous_status) and previous_status != ticket_case.status
        if status_changed:
            note_resp = case_client.add_task_log(
                message=f"[workflow] SATRIA status updated: {previous_status} -> {ticket_case.status}",
                cid=remote_case_id,
            )
            if activity is not None:
                activity.remote_note_id = str(
                    _response_field(note_resp, "id")
                    or _response_field(note_resp, "log_id")
                    or activity.remote_note_id
                    or ""
                )

        if ticket_case.resolution_summary:
            case_client.set_summary(ticket_case.resolution_summary, cid=remote_case_id)

        if ticket_case.status == "Closed":
            case_client.close_case(case_id=remote_case_id)
        else:
            case_client.reopen_case(case_id=remote_case_id)

        ticket_case.last_sync_status = "synced"
        ticket_case.last_sync_error = None
    except Exception as exc:
        ticket_case.last_sync_status = "failed"
        ticket_case.last_sync_error = str(exc)

    return ticket_case


def delete_remote_ticket_case(ticket_case: TicketCase) -> dict[str, str | bool]:
    if not (ticket_case.remote_case_id or ticket_case.remote_alert_id):
        return {
            "ok": True,
            "status": "skipped",
            "message": "no remote mapping",
        }

    if not _can_use_iris_api():
        return {
            "ok": False,
            "status": "unavailable",
            "message": "IRIS API not configured or unreachable from SATRIA runtime",
        }

    deleted_case = False
    deleted_alert = False
    errors: list[str] = []

    try:
        session = _client_session()
        case_client = Case(session, case_id=_as_int(ticket_case.remote_case_id))
        alert_client = Alert(session)

        remote_case_id = _as_int(ticket_case.remote_case_id)
        remote_alert_id = _as_int(ticket_case.remote_alert_id)

        if remote_case_id:
            try:
                case_client.delete_case(cid=remote_case_id)
                deleted_case = True
            except Exception as exc:
                errors.append(f"case {remote_case_id}: {exc}")

        if remote_alert_id:
            try:
                alert_client.delete_alert(remote_alert_id)
                deleted_alert = True
            except Exception as exc:
                errors.append(f"alert {remote_alert_id}: {exc}")
    except Exception as exc:
        return {
            "ok": False,
            "status": "failed",
            "message": str(exc),
        }

    if errors:
        return {
            "ok": False,
            "status": "partial-failed",
            "message": "; ".join(errors),
        }

    return {
        "ok": True,
        "status": "deleted",
        "message": f"case_deleted={deleted_case}; alert_deleted={deleted_alert}",
    }


def sync_ticket_case(db: Session, ticket_case: TicketCase) -> TicketCase:
    if not _can_use_iris_api():
        _apply_stub_sync(ticket_case)
        return ticket_case

    try:
        session = ClientSession(
            apikey=settings.iris_api_key,
            host=settings.iris_url,
            ssl_verify=settings.iris_verify_ssl,
            agent="SATRIA",
        )
        case_client = Case(session, case_id=_as_int(ticket_case.remote_case_id))
        alert_client = Alert(session)
        customer_client = Customer(session)
        classification_helper = CaseClassificationsHelper(session)
        user_client = User(session)

        remote_customer_id = _ensure_customer(customer_client)
        ticket_case.remote_case_soc_id = ticket_case.remote_case_soc_id or default_soc_id_for_case(ticket_case)
        existing_remote_case = find_remote_case_by_soc_id(ticket_case.remote_case_soc_id)
        if existing_remote_case and not ticket_case.remote_case_id:
            ticket_case.remote_case_id = str(existing_remote_case.get("case_id") or "")
            ticket_case.remote_case_name = existing_remote_case.get("case_name") or ticket_case.remote_case_name or ticket_case.title
            ticket_case.remote_customer_id = str(existing_remote_case.get("customer_id") or ticket_case.remote_customer_id or "")
            case_client.set_cid(int(ticket_case.remote_case_id))

        if not ticket_case.remote_alert_id and ticket_case.finding:
            alert_resp = alert_client.add_alert(_alert_payload(ticket_case.finding, ticket_case.asset))
            ticket_case.remote_alert_id = str(
                _response_field(alert_resp, "alert_id")
                or _response_field(alert_resp, ["alert", "alert_id"])
                or ticket_case.remote_alert_id
                or ""
            )

        if not ticket_case.remote_case_id:
            classification = _resolve_case_classification(classification_helper, ticket_case)
            case_resp = case_client.add_case(
                case_name=ticket_case.title,
                case_description=ticket_case.description or ticket_case.title,
                case_customer=int(remote_customer_id) if remote_customer_id else settings.iris_customer_name,
                case_classification=classification,
                soc_id=ticket_case.remote_case_soc_id,
                create_customer=not bool(remote_customer_id),
            )
            ticket_case.remote_case_id = str(_response_field(case_resp, "case_id") or _response_field(case_resp, ["case", "case_id"]) or "")
            ticket_case.remote_case_soc_id = str(_response_field(case_resp, "soc_id") or _response_field(case_resp, ["case", "soc_id"]) or ticket_case.remote_case_soc_id or "")
            ticket_case.remote_case_name = str(_response_field(case_resp, "case_name") or ticket_case.title)
            ticket_case.remote_customer_id = str(remote_customer_id or _response_field(case_resp, "customer_id") or "")
            case_client.set_cid(int(ticket_case.remote_case_id))

        _sync_case_metadata(case_client, user_client, classification_helper, ticket_case)
        _ensure_note_directory(case_client, ticket_case)
        _ensure_evidence_folder(case_client, ticket_case)
        _sync_tasks(case_client, user_client, ticket_case)
        _sync_activities(case_client, ticket_case)
        _sync_evidences(case_client, ticket_case)

        if ticket_case.resolution_summary:
            case_client.set_summary(ticket_case.resolution_summary, cid=int(ticket_case.remote_case_id))
        elif ticket_case.description:
            case_client.set_summary(ticket_case.description, cid=int(ticket_case.remote_case_id))

        if ticket_case.status == "Closed":
            case_client.close_case(case_id=int(ticket_case.remote_case_id))
        else:
            case_client.reopen_case(case_id=int(ticket_case.remote_case_id))

        ticket_case.last_sync_status = "synced"
        ticket_case.last_sync_error = None
    except Exception as exc:  # pragma: no cover - live API error path
        matched = find_remote_case_by_soc_id(ticket_case.remote_case_soc_id or default_soc_id_for_case(ticket_case))
        if matched and not ticket_case.remote_case_id:
            ticket_case.remote_case_id = str(matched.get("case_id") or "")
            ticket_case.remote_case_name = matched.get("case_name") or ticket_case.remote_case_name
            ticket_case.last_sync_status = "partial-synced"
            ticket_case.last_sync_error = str(exc)
            return ticket_case
        ticket_case.last_sync_status = "failed"
        ticket_case.last_sync_error = str(exc)

    return ticket_case


def _apply_stub_sync(ticket_case: TicketCase):
    stamp = int(datetime.utcnow().timestamp())
    if not ticket_case.remote_alert_id and ticket_case.finding_id:
        ticket_case.remote_alert_id = f"IRIS-STUB-ALERT-{ticket_case.finding_id}-{stamp}"
    if not ticket_case.remote_case_id:
        ticket_case.remote_case_id = f"IRIS-STUB-CASE-{ticket_case.id}-{stamp}"
    ticket_case.remote_customer_id = ticket_case.remote_customer_id or "IRIS-STUB-CUSTOMER"
    ticket_case.remote_case_name = ticket_case.remote_case_name or ticket_case.title
    ticket_case.remote_case_soc_id = ticket_case.remote_case_soc_id or f"SOC-{ticket_case.id}"
    ticket_case.remote_notes_directory_id = ticket_case.remote_notes_directory_id or f"IRIS-STUB-NOTE-DIR-{ticket_case.id}"
    ticket_case.remote_evidence_folder_id = ticket_case.remote_evidence_folder_id or f"IRIS-STUB-EVIDENCE-DIR-{ticket_case.id}"
    ticket_case.last_sync_status = "stubbed"
    ticket_case.last_sync_error = None

    for task in ticket_case.tasks:
        task.remote_task_id = task.remote_task_id or f"IRIS-STUB-TASK-{ticket_case.id}-{task.id}"
    for evidence in ticket_case.evidences:
        evidence.remote_evidence_id = evidence.remote_evidence_id or f"IRIS-STUB-EVIDENCE-{ticket_case.id}-{evidence.id}"
        evidence.remote_file_id = evidence.remote_file_id or f"IRIS-STUB-FILE-{ticket_case.id}-{evidence.id}"
    for activity in ticket_case.activities:
        activity.remote_note_id = activity.remote_note_id or f"IRIS-STUB-LOG-{ticket_case.id}-{activity.id}"


def _can_use_iris_api() -> bool:
    return bool(settings.iris_url and settings.iris_api_key and ClientSession and Case and Alert)


def _client_session() -> ClientSession:
    return ClientSession(
        apikey=settings.iris_api_key,
        host=settings.iris_url,
        ssl_verify=settings.iris_verify_ssl,
        agent="SATRIA",
    )


def _sync_case_metadata(case_client: Case, user_client: User, classification_helper: CaseClassificationsHelper, ticket_case: TicketCase):
    classification = _resolve_case_classification(classification_helper, ticket_case)
    owner_ids = _resolve_user_ids(user_client, ticket_case.current_owner)
    ticket_case.remote_case_soc_id = ticket_case.remote_case_soc_id or default_soc_id_for_case(ticket_case)
    case_client.update_case(
        case_id=int(ticket_case.remote_case_id),
        case_name=ticket_case.title,
        case_description=ticket_case.description or ticket_case.title,
        case_classification=classification,
        case_owner=owner_ids[0] if owner_ids else ticket_case.current_owner,
        soc_id=ticket_case.remote_case_soc_id,
        case_tags=tags_for_case(ticket_case),
    )


def _ensure_customer(customer_client: Customer) -> str | None:
    lookup = customer_client.lookup_customer(settings.iris_customer_name)
    customer_id = _response_field(lookup, "customer_id")
    if customer_id:
        return str(customer_id)
    return None


def _ensure_note_directory(case_client: Case, ticket_case: TicketCase):
    if ticket_case.remote_notes_directory_id:
        return
    dirs_resp = case_client.list_notes_directories(cid=int(ticket_case.remote_case_id))
    directories = dirs_resp.get_data() or []
    for item in directories:
        if item.get("name") == settings.iris_note_directory:
            ticket_case.remote_notes_directory_id = str(item.get("id"))
            return
    add_resp = case_client.add_notes_directory(settings.iris_note_directory, cid=int(ticket_case.remote_case_id))
    ticket_case.remote_notes_directory_id = str(_response_field(add_resp, "id") or _response_field(add_resp, "directory_id") or "")


def _ensure_evidence_folder(case_client: Case, ticket_case: TicketCase):
    if ticket_case.remote_evidence_folder_id:
        return
    tree_resp = case_client.list_ds_tree(cid=int(ticket_case.remote_case_id))
    folder_id = _find_tree_node_id(tree_resp.get_data(), settings.iris_evidence_folder) or _find_tree_node_id(tree_resp.get_data(), "Evidences")
    if folder_id:
        ticket_case.remote_evidence_folder_id = str(folder_id)
        return
    add_resp = case_client.add_ds_folder(parent_id=0, folder_name=settings.iris_evidence_folder, cid=int(ticket_case.remote_case_id))
    ticket_case.remote_evidence_folder_id = str(_response_field(add_resp, "id") or _response_field(add_resp, "folder_id") or "")


def _sync_tasks(case_client: Case, user_client: User, ticket_case: TicketCase):
    cid = int(ticket_case.remote_case_id)
    for task in sorted(ticket_case.tasks, key=lambda item: (item.sort_order, item.id)):
        assignees = _resolve_user_ids(user_client, task.assignees)
        if not task.remote_task_id:
            resp = case_client.add_task(
                title=task.title,
                status=_normalize_task_status(task.status or settings.iris_task_status),
                assignees=assignees or [settings.soc_l1_user],
                description=task.description,
                tags=_csv_to_list(task.tags),
                cid=cid,
            )
            task.remote_task_id = str(_response_field(resp, "task_id") or _response_field(resp, ["task", "task_id"]) or _response_field(resp, "id") or "")
        else:
            case_client.update_task(
                task_id=int(task.remote_task_id),
                title=task.title,
                status=_normalize_task_status(task.status or settings.iris_task_status),
                assignees=assignees or None,
                description=task.description,
                tags=_csv_to_list(task.tags),
                cid=cid,
            )


def _sync_activities(case_client: Case, ticket_case: TicketCase):
    cid = int(ticket_case.remote_case_id)
    for activity in ticket_case.activities:
        if activity.remote_note_id:
            continue
        resp = case_client.add_task_log(
            message=f"[{activity.actor_role or 'system'}] {activity.actor}: {activity.message}",
            cid=cid,
        )
        activity.remote_note_id = str(_response_field(resp, "id") or _response_field(resp, "log_id") or f"log-{activity.id}")


def _sync_evidences(case_client: Case, ticket_case: TicketCase):
    cid = int(ticket_case.remote_case_id)
    folder_id = _as_int(ticket_case.remote_evidence_folder_id) or 0
    for evidence in ticket_case.evidences:
        if not evidence.remote_evidence_id:
            resp = case_client.add_evidence(
                filename=evidence.filename,
                file_size=evidence.file_size or 0,
                description=evidence.description,
                file_hash=evidence.file_hash,
                cid=cid,
            )
            evidence.remote_evidence_id = str(_response_field(resp, "evidence_id") or _response_field(resp, ["evidence", "evidence_id"]) or _response_field(resp, "id") or "")
        if evidence.source_path and not evidence.remote_file_id:
            path = Path(evidence.source_path)
            if path.exists() and path.is_file():
                with path.open("rb") as handle:
                    file_resp = case_client.add_ds_file(
                        parent_id=folder_id,
                        file_stream=handle,
                        filename=evidence.filename,
                        file_description=evidence.description or evidence.filename,
                        file_is_ioc=False,
                        file_is_evidence=True,
                        file_tags=["satria", "evidence"],
                        cid=cid,
                    )
                evidence.remote_file_id = str(_response_field(file_resp, "file_id") or _response_field(file_resp, ["file", "file_id"]) or _response_field(file_resp, "id") or "")


def _resolve_user_ids(user_client: User, assignees: str | None) -> list[int | str]:
    resolved: list[int | str] = []
    known_users = user_client.list_users().get_data() or []
    for assignee in _csv_to_list(assignees):
        lookup = user_client.lookup_username(assignee)
        user_id = _response_field(lookup, "user_id") or _response_field(lookup, ["user", "user_id"])
        if not user_id:
            for user in known_users:
                if user.get("user_name") == assignee or user.get("user_login") == assignee:
                    user_id = user.get("user_id") or user.get("id")
                    break
        resolved.append(int(user_id) if user_id else assignee)
    return resolved


def _csv_to_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _resolve_case_classification(helper: CaseClassificationsHelper, ticket_case: TicketCase):
    configured = settings.iris_case_classification
    if configured:
        resolved = helper.lookup_case_classification_name(configured)
        if resolved:
            return resolved

    if ticket_case.case_kind == "manual":
        mapping = {
            "malware-endpoint": "malicious-code:trojan-malware",
            "phishing-email": "fraud:phishing",
        }
        resolved = helper.lookup_case_classification_name(mapping.get(ticket_case.incident_type or "", "other:other"))
        if resolved:
            return resolved

    resolved = helper.lookup_case_classification_name("vulnerable:vulnerable-service")
    return resolved or 36


def _alert_payload(finding: Finding, asset: Asset) -> dict:
    return {
        "alert_title": f"[{finding.severity_normalized}] {finding.title}",
        "alert_description": finding.description or finding.evidence or finding.title,
        "alert_source": f"SATRIA/{finding.scanner}",
        "alert_source_ref": str(finding.id),
        "alert_severity_id": severity_to_iris_id(finding.severity_normalized),
        "alert_status_id": 2,
        "alert_context": {
            "asset_name": asset.name,
            "asset_type": asset.asset_type,
            "target": asset.target,
            "environment": asset.environment,
            "cve": finding.cve,
            "cwe": finding.cwe,
            "risk_score": finding.risk_score,
            "recommendation": finding.recommendation,
            "evidence": finding.evidence,
        },
    }


def _as_int(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None


def _response_field(response, path):
    try:
        value = response.get_data_field(path)
        if value not in (None, "", []):
            return value
    except Exception:
        pass

    data = response.get_data()
    if isinstance(path, list):
        for key in path:
            if isinstance(data, dict):
                data = data.get(key)
            else:
                data = None
                break
        return data

    if isinstance(data, dict):
        return data.get(path)
    return None


def _normalize_task_status(status: str | None) -> str:
    mapping = {
        "to be done": "To do",
        "todo": "To do",
        "to do": "To do",
        "in progress": "In progress",
        "done": "Done",
        "closed": "Done",
        "cancelled": "Canceled",
        "canceled": "Canceled",
        "on hold": "On hold",
    }
    normalized = (status or "To do").strip()
    return mapping.get(normalized.lower(), normalized)


def _find_tree_node_id(tree, wanted_name: str):
    if isinstance(tree, dict):
        for node_id, node in tree.items():
            if not isinstance(node, dict):
                continue
            if node.get("name") == wanted_name:
                return str(node_id).split("-", 1)[-1]
            child_match = _find_tree_node_id(node.get("children"), wanted_name)
            if child_match:
                return child_match
    elif isinstance(tree, list):
        for node in tree:
            if isinstance(node, dict):
                if node.get("name") == wanted_name:
                    return node.get("id")
                child_match = _find_tree_node_id(node.get("children"), wanted_name)
                if child_match:
                    return child_match
    return None


def severity_to_iris_id(severity: str) -> int:
    return {
        "Informational": 1,
        "Low": 2,
        "Medium": 3,
        "High": 4,
        "Critical": 5,
    }.get(severity, 3)
