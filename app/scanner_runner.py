import ipaddress
import json
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import docker
from docker.errors import DockerException, NotFound

try:
    from gvm.connections import TLSConnection, UnixSocketConnection
    from gvm.errors import GvmError
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
except ImportError:  # pragma: no cover - handled at runtime in scanner guard
    TLSConnection = UnixSocketConnection = Gmp = EtreeTransform = None

    class GvmError(Exception):
        pass

from .config import get_settings
from .allowlist import effective_allowlist_rules

settings = get_settings()

PROFILE_SCANNERS = {
    'quick_container': ['trivy'],
    'sbom_scan': ['syft', 'grype'],
    'full_container': ['trivy', 'syft', 'grype'],
    'repo_security': ['trivy', 'syft'],
    'web_baseline': ['zap'],
    'web_full': ['zap'],
    'infra_va': ['openvas'],
    'retest': ['trivy'],
}


SUPPORTED_PROFILES = tuple(PROFILE_SCANNERS.keys())


def scanners_for_profile(profile: str) -> list[str]:
    scanners = PROFILE_SCANNERS.get(profile)
    if not scanners:
        raise ValueError(f'unsupported scan profile: {profile}')
    return scanners


def is_allowed_target(target: str) -> bool:
    allowlist = effective_allowlist_rules()
    if not allowlist:
        return False

    host = extract_host(target)
    host_ip = _parse_ip(host)
    network_style = bool(host and (host_ip or '.' in host or ':' in host or '://' in target))

    for rule in allowlist:
        parsed_rule_host = extract_host(rule)
        rule_network = _parse_network(rule)
        if host_ip and rule_network and host_ip in rule_network:
            return True
        if host_ip and parsed_rule_host and host_ip == _parse_ip(parsed_rule_host):
            return True
        if network_style:
            if parsed_rule_host and host and host.lower() == parsed_rule_host.lower():
                return True
            if parsed_rule_host.startswith('.') and host.lower().endswith(parsed_rule_host.lower()):
                return True
            if parsed_rule_host and host.lower().endswith(f'.{parsed_rule_host.lower()}'):
                return True
        elif rule in target:
            return True
    return False


def run_command(command: list[str], output_path: Path | None = None, timeout: int = 900) -> tuple[bool, str]:
    try:
        if output_path:
            with output_path.open('w', encoding='utf-8') as fh:
                proc = subprocess.run(command, stdout=fh, stderr=subprocess.PIPE, text=True, timeout=timeout)
        else:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        if proc.returncode == 0:
            return True, proc.stderr if output_path else proc.stdout
        return False, proc.stderr or proc.stdout
    except Exception as exc:
        return False, str(exc)


def run_scanner(scanner: str, asset_type: str, target: str, report_dir: str, scan_id: int, profile: str) -> tuple[Path, dict[str, Any], str]:
    report_base = Path(report_dir)
    report_base.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    path = report_base / f'scan-{scan_id}-{scanner}-{timestamp}.json'

    if settings.demo_mode:
        payload = sample_payload(scanner, target)
        path.write_text(json.dumps(payload, indent=2), encoding='utf-8')
        return path, payload, 'demo_mode: sample payload generated'

    prepared_target = prepare_target(scanner, target, profile)

    if not is_allowed_target(prepared_target):
        raise RuntimeError(f'target not in allowlist: {prepared_target}')

    if scanner == 'trivy':
        payload, msg = run_trivy(asset_type, target, path)
    elif scanner == 'syft':
        payload, msg = run_syft(asset_type, target, path)
    elif scanner == 'grype':
        payload, msg = run_grype(asset_type, target, path)
    elif scanner == 'zap':
        payload, msg = run_zap(prepared_target, path, profile)
    elif scanner == 'openvas':
        payload, msg = run_openvas(prepared_target, path)
    else:
        raise RuntimeError(f'unknown scanner configured: {scanner}')
    return path, payload, msg


def prepare_target(scanner: str, target: str, profile: str) -> str:
    if scanner == 'zap':
        return normalize_web_target(target, allow_active=(profile == 'web_full'))
    if scanner == 'openvas':
        return normalize_network_target(target)
    return target.strip()


def load_json_or_sample(path: Path, scanner: str, target: str, msg: str) -> tuple[dict[str, Any], str]:
    try:
        return json.loads(path.read_text(encoding='utf-8')), msg
    except Exception:
        raise RuntimeError(f'{scanner} produced invalid JSON output for target {target}')


def run_trivy(asset_type: str, target: str, path: Path) -> tuple[dict[str, Any], str]:
    if not shutil.which('trivy'):
        raise RuntimeError('trivy is not installed in worker container')
    mode = 'image'
    if asset_type in {'source_repository', 'repository'}:
        mode = 'repo'
    elif asset_type in {'filesystem', 'folder'}:
        mode = 'fs'
    cache_dir = Path('/tmp') / f'trivy-cache-{path.stem}'
    cache_dir.mkdir(parents=True, exist_ok=True)
    cmd = ['trivy', mode, '--cache-dir', str(cache_dir), '--scanners', 'vuln', '--format', 'json', '--output', str(path), target]
    ok, msg = run_command(cmd, timeout=1200)
    if not ok:
        raise RuntimeError(f'trivy failed for target {target}: {msg}')
    return load_json_or_sample(path, 'trivy', target, msg)


def run_syft(asset_type: str, target: str, path: Path) -> tuple[dict[str, Any], str]:
    if not shutil.which('syft'):
        raise RuntimeError('syft is not installed in worker container')
    cmd = ['syft', syft_grype_target(asset_type, target), '-o', 'json']
    ok, msg = run_command(cmd, output_path=path, timeout=900)
    if not ok:
        raise RuntimeError(f'syft failed for target {target}: {msg}')
    return load_json_or_sample(path, 'syft', target, msg)


def run_grype(asset_type: str, target: str, path: Path) -> tuple[dict[str, Any], str]:
    if not shutil.which('grype'):
        raise RuntimeError('grype is not installed in worker container')
    cmd = ['grype', syft_grype_target(asset_type, target), '-o', 'json']
    ok, msg = run_command(cmd, output_path=path, timeout=900)
    if not ok:
        raise RuntimeError(f'grype failed for target {target}: {msg}')
    return load_json_or_sample(path, 'grype', target, msg)


def syft_grype_target(asset_type: str, target: str) -> str:
    if asset_type == 'container_image' and '://' not in target and not target.startswith(('docker:', 'registry:', 'oci-archive:', 'dir:')):
        return f'docker:{target}'
    return target


def run_zap(target: str, path: Path, profile: str) -> tuple[dict[str, Any], str]:
    if profile == 'web_full' and not settings.allow_active_scan:
        raise RuntimeError('active scan disabled by policy: set ALLOW_ACTIVE_SCAN=true only for approved targets')

    script = 'zap-full-scan.py' if profile == 'web_full' else 'zap-baseline.py'
    if shutil.which(script):
        cmd = [script, '-t', target, '-J', str(path)]
        ok, msg = run_command(cmd, timeout=1800)
    elif shutil.which('docker') and is_container_running(settings.zap_container_name):
        cmd = ['docker', 'exec', settings.zap_container_name, script, '-t', target, '-J', path.name]
        ok, msg = run_command(cmd, timeout=1800)
    elif is_container_running(settings.zap_container_name):
        ok, msg = run_zap_via_docker_sdk(settings.zap_container_name, script, target, path)
    else:
        raise RuntimeError(
            'OWASP ZAP runner not available. Start the optional zap container (`docker compose --profile scanner up -d zap`) '
            'or install zap-baseline.py/zap-full-scan.py in the worker image.'
        )

    if not ok:
        if path.exists():
            return load_json_or_sample(path, 'zap', target, msg)
        raise RuntimeError(f'zap failed for target {target}: {msg}')
    return load_json_or_sample(path, 'zap', target, msg)


def run_openvas(target: str, path: Path) -> tuple[dict[str, Any], str]:
    if Gmp is None or EtreeTransform is None:
        raise RuntimeError('python-gvm is not installed in worker container')
    if not (settings.greenbone_username and settings.greenbone_password):
        raise RuntimeError(
            'Greenbone/OpenVAS connector not configured. Fill GREENBONE_USERNAME and GREENBONE_PASSWORD, '
            'then point SATRIA to gvmd using GREENBONE_SOCKET_PATH or GREENBONE_HOST.'
        )
    connection = _greenbone_connection()
    target_id = None
    task_id = None
    task_name = f'SATRIA scan {path.stem}'
    try:
        with Gmp(connection, transform=EtreeTransform()) as gmp:
            gmp.authenticate(settings.greenbone_username, settings.greenbone_password)
            config_id = _first_entity_id(gmp.get_scan_configs(details=False), 'config', settings.greenbone_scan_config)
            scanner_id = _first_entity_id(gmp.get_scanners(details=False), 'scanner', settings.greenbone_scanner_name)
            port_list_id = _first_entity_id(gmp.get_port_lists(details=False), 'port_list', settings.greenbone_port_list)
            target_id = _create_openvas_target(gmp, task_name, target, port_list_id)
            task_id = _create_openvas_task(gmp, task_name, target_id, config_id, scanner_id)
            gmp.start_task(task_id)
            report_id, final_status = _wait_for_openvas_report(gmp, task_id)
            if not report_id:
                raise RuntimeError(f'Greenbone task finished without report id. final_status={final_status}')
            report_xml = gmp.get_report(report_id, ignore_pagination=True, details=True)
            payload = _parse_openvas_report(report_xml, target)
            path.write_text(json.dumps(payload, indent=2), encoding='utf-8')
            finding_count = len(payload.get('results', []))
            return payload, f'openvas: status={final_status} findings={finding_count} report_id={report_id}'
    except GvmError as exc:
        raise RuntimeError(f'Greenbone GMP request failed: {exc}') from exc
    except Exception as exc:
        raise RuntimeError(f'Greenbone/OpenVAS scan failed for target {target}: {exc}') from exc
    finally:
        if Gmp is not None and EtreeTransform is not None:
            try:
                cleanup_connection = _greenbone_connection()
                with Gmp(cleanup_connection, transform=EtreeTransform()) as gmp:
                    gmp.authenticate(settings.greenbone_username, settings.greenbone_password)
                    if task_id:
                        try:
                            gmp.delete_task(task_id, ultimate=True)
                        except Exception:
                            pass
                    if target_id:
                        try:
                            gmp.delete_target(target_id, ultimate=True)
                        except Exception:
                            pass
            except Exception:
                pass


def sample_payload(scanner: str, target: str, reason: str = 'demo') -> dict[str, Any]:
    if scanner == 'trivy':
        return {
            'SchemaVersion': 2,
            'ArtifactName': target,
            'Results': [
                {
                    'Target': target,
                    'Class': 'os-pkgs',
                    'Type': 'debian',
                    'Vulnerabilities': [
                        {
                            'VulnerabilityID': 'CVE-2024-DEMO-0001',
                            'PkgName': 'openssl',
                            'InstalledVersion': '1.1.1-demo',
                            'FixedVersion': '1.1.1z-demo',
                            'Severity': 'CRITICAL',
                            'Title': 'Demo vulnerable OpenSSL package',
                            'Description': f'Demo finding generated for {target}. Reason: {reason}',
                            'CVSS': {'nvd': {'V3Score': 9.8}},
                        },
                    ],
                    'Secrets': [
                        {
                            'RuleID': 'demo-secret',
                            'Title': 'Demo potential secret in repository',
                            'Severity': 'HIGH',
                            'StartLine': 12,
                            'Match': 'AKIA****************',
                        }
                    ] if 'repo' in target or 'github' in target else [],
                }
            ]
        }
    if scanner == 'grype':
        return {
            'matches': [
                {
                    'vulnerability': {
                        'id': 'CVE-2024-DEMO-0002',
                        'severity': 'High',
                        'description': f'Demo Grype vulnerability for {target}. Reason: {reason}',
                        'fix': {'versions': ['2.0.0-demo']},
                        'cvss': [{'metrics': {'baseScore': 8.1}}],
                    },
                    'artifact': {
                        'name': 'log4j-core',
                        'version': '2.14.1-demo',
                        'type': 'java-archive',
                        'locations': [{'path': '/app/lib/log4j-core.jar'}],
                    },
                }
            ]
        }
    if scanner == 'syft':
        return {
            'artifacts': [
                {'name': 'openssl', 'version': '1.1.1-demo', 'type': 'deb', 'purl': 'pkg:deb/debian/openssl@1.1.1-demo'},
                {'name': 'log4j-core', 'version': '2.14.1-demo', 'type': 'java-archive', 'purl': 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1-demo'},
                {'name': 'fastapi', 'version': '0.115.6', 'type': 'python', 'purl': 'pkg:pypi/fastapi@0.115.6'},
            ]
        }
    if scanner == 'zap':
        return {
            'site': [
                {
                    '@name': target,
                    'alerts': [
                        {
                            'alert': 'Content Security Policy Header Not Set',
                            'riskdesc': 'Medium (Medium)',
                            'desc': 'Demo ZAP finding: CSP header is missing.',
                            'solution': 'Configure Content-Security-Policy header.',
                            'cweid': '693',
                            'instances': [{'uri': target, 'evidence': 'Content-Security-Policy header missing'}],
                        },
                        {
                            'alert': 'Cookie without HttpOnly Flag',
                            'riskdesc': 'Low (Medium)',
                            'desc': 'Demo cookie flag finding.',
                            'solution': 'Set HttpOnly and Secure attribute on session cookies.',
                            'cweid': '1004',
                            'instances': [{'uri': target, 'param': 'SESSIONID'}],
                        },
                    ],
                }
            ]
        }
    if scanner == 'openvas':
        return {
            'results': [
                {
                    'host': target,
                    'port': '443/tcp',
                    'name': 'Demo weak TLS configuration',
                    'description': f'Demo OpenVAS finding generated for {target}. Reason: {reason}',
                    'severity_label': 'High',
                    'cvss': '7.5',
                    'cve': None,
                    'nvt_oid': '1.3.6.1.4.1.25623.1.0.demo',
                    'solution': 'Disable weak protocols/ciphers and apply service hardening.',
                }
            ]
        }
    return {'results': []}


def run_zap_via_docker_sdk(container_name: str, script: str, target: str, path: Path) -> tuple[bool, str]:
    try:
        client = docker.from_env()
        container = client.containers.get(container_name)
        command = [script, '-t', target, '-J', path.name]
        result = container.exec_run(command, user='0:0', demux=True)
        stdout, stderr = result.output if result.output else (b'', b'')
        output_text = '\n'.join(
            chunk.decode('utf-8', errors='replace').strip()
            for chunk in (stdout, stderr)
            if chunk
        ).strip()
        return result.exit_code == 0, output_text
    except NotFound as exc:
        return False, f'ZAP container not found: {exc}'
    except DockerException as exc:
        return False, f'Docker SDK failed to execute ZAP: {exc}'


def normalize_web_target(target: str, allow_active: bool) -> str:
    candidate = target.strip()
    if '://' not in candidate:
        candidate = f'http://{candidate}'
    parsed = urlparse(candidate)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
        raise RuntimeError('web target must be a valid http/https URL for OWASP ZAP')
    if allow_active and parsed.scheme != 'http' and parsed.scheme != 'https':
        raise RuntimeError('active web scan requires http/https URL')
    return parsed.geturl()


def normalize_network_target(target: str) -> str:
    host = extract_host(target)
    if not host:
        raise RuntimeError('infrastructure target must be a hostname or IP address')
    return host


def extract_host(target: str) -> str:
    value = target.strip()
    if '://' in value:
        parsed = urlparse(value)
        return parsed.hostname or ''
    parsed = urlparse(f'//{value}')
    if parsed.hostname:
        return parsed.hostname
    return value.split('/')[0].split(':')[0]


def _parse_ip(value: str | None):
    if not value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _parse_network(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def is_container_running(container_name: str) -> bool:
    try:
        client = docker.from_env()
        container = client.containers.get(container_name)
        return container.status == 'running'
    except NotFound:
        return False
    except DockerException:
        pass

    cmd = ['docker', 'ps', '--filter', f'name=^{container_name}$', '--format', '{{.Names}}']
    ok, output = run_command(cmd, timeout=30)
    if not ok:
        return False
    return any(line.strip() == container_name for line in output.splitlines())


def _greenbone_connection():
    socket_path = (settings.greenbone_socket_path or '').strip()
    if socket_path:
        socket_file = Path(socket_path)
        if socket_file.exists():
            return UnixSocketConnection(path=socket_path, timeout=settings.greenbone_timeout)
    if settings.greenbone_host:
        return TLSConnection(hostname=settings.greenbone_host, port=settings.greenbone_port, timeout=settings.greenbone_timeout)
    raise RuntimeError(
        'Greenbone connection not configured. Provide GREENBONE_SOCKET_PATH to mounted gvmd.sock '
        'or GREENBONE_HOST/GREENBONE_PORT for a TCP endpoint.'
    )


def _first_entity_id(root: Any, tag_name: str, preferred_name: str | None = None) -> str:
    candidates = root.findall(f'.//{tag_name}')
    if not candidates:
        raise RuntimeError(f'Greenbone response did not contain any <{tag_name}> entries')
    preferred = (preferred_name or '').strip().lower()
    for item in candidates:
        if preferred and (item.findtext('name') or '').strip().lower() == preferred:
            entity_id = item.get('id')
            if entity_id:
                return entity_id
    entity_id = candidates[0].get('id')
    if not entity_id:
        raise RuntimeError(f'Greenbone response for <{tag_name}> did not include id')
    return entity_id


def _create_openvas_target(gmp: Any, name: str, target: str, port_list_id: str) -> str:
    response = gmp.create_target(
        name,
        hosts=[target],
        comment=f'Created by SATRIA for target {target}',
        port_list_id=port_list_id,
    )
    target_id = response.get('id')
    if not target_id:
        raise RuntimeError('Greenbone create_target did not return target id')
    return target_id


def _create_openvas_task(gmp: Any, name: str, target_id: str, config_id: str, scanner_id: str) -> str:
    response = gmp.create_task(
        name,
        config_id=config_id,
        target_id=target_id,
        scanner_id=scanner_id,
        comment='Created by SATRIA automation',
    )
    task_id = response.get('id')
    if not task_id:
        raise RuntimeError('Greenbone create_task did not return task id')
    return task_id


def _wait_for_openvas_report(gmp: Any, task_id: str) -> tuple[str | None, str]:
    deadline = time.time() + settings.greenbone_max_wait_seconds
    last_status = 'Queued'
    while time.time() < deadline:
        task_xml = gmp.get_task(task_id)
        status = (task_xml.findtext('.//task/status') or task_xml.findtext('.//status') or '').strip() or last_status
        last_status = status
        lower_status = status.lower()
        report_id = _report_id_from_task_xml(task_xml)
        if lower_status == 'done':
            return report_id, status
        if lower_status in {'stopped', 'interrupted', 'delete requested', 'deleted'}:
            raise RuntimeError(f'Greenbone task stopped unexpectedly with status {status}')
        time.sleep(max(settings.greenbone_poll_interval, 5))
    raise RuntimeError(f'Greenbone task timeout after {settings.greenbone_max_wait_seconds}s. last_status={last_status}')


def _report_id_from_task_xml(task_xml: Any) -> str | None:
    report_node = task_xml.find('.//task/last_report/report')
    if report_node is None:
        report_node = task_xml.find('.//last_report/report')
    if report_node is not None and report_node.get('id'):
        return report_node.get('id')
    report_node = task_xml.find('.//report')
    if report_node is not None and report_node.get('id'):
        return report_node.get('id')
    return None


def _parse_openvas_report(report_xml: Any, target: str) -> dict[str, Any]:
    results = []
    for item in report_xml.findall('.//result'):
        host = (item.findtext('host') or target).strip()
        port = (item.findtext('port') or '').strip() or None
        threat = (item.findtext('threat') or '').strip() or None
        severity_value = (item.findtext('severity') or '').strip() or None
        nvt = item.find('nvt')
        refs = nvt.findall('.//ref') if nvt is not None else []
        cve_refs = [ref.get('id') for ref in refs if (ref.get('type') or '').lower() == 'cve' and ref.get('id')]
        cvss_base = None
        if nvt is not None:
            cvss_base = (nvt.findtext('cvss_base') or '').strip() or None
        results.append({
            'host': host,
            'port': port,
            'name': (item.findtext('name') or (nvt.findtext('name') if nvt is not None else '') or 'OpenVAS finding').strip(),
            'description': (item.findtext('description') or '').strip() or None,
            'severity_label': _openvas_severity_label(threat, severity_value),
            'cvss': cvss_base or severity_value,
            'cve': ', '.join(cve_refs) if cve_refs else None,
            'nvt_oid': nvt.get('oid') if nvt is not None else None,
            'solution': (nvt.findtext('solution') if nvt is not None else None) or None,
            'threat': threat,
            'evidence': (item.findtext('qod/value') or '').strip() or None,
        })
    return {
        'target': target,
        'generated_at': datetime.utcnow().isoformat(),
        'results': results,
    }


def _openvas_severity_label(threat: str | None, severity_value: str | None) -> str:
    if threat:
        normalized = threat.strip().lower()
        if normalized in {'critical', 'high', 'medium', 'low', 'log', 'info'}:
            return 'Informational' if normalized in {'log', 'info'} else normalized.capitalize()
    if not severity_value:
        return 'Medium'
    try:
        score = float(severity_value)
    except ValueError:
        return severity_value.capitalize()
    if score >= 9.0:
        return 'Critical'
    if score >= 7.0:
        return 'High'
    if score >= 4.0:
        return 'Medium'
    if score > 0:
        return 'Low'
    return 'Informational'
