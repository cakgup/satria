import hashlib
from typing import Any
from .risk import normalize_severity, risk_score

FindingDict = dict[str, Any]

def make_dedup_key(asset_id: int, scanner: str, item: FindingDict) -> str:
    raw = '|'.join([
        str(asset_id),
        scanner,
        str(item.get('finding_type') or ''),
        str(item.get('cve') or item.get('cwe') or ''),
        str(item.get('package_name') or ''),
        str(item.get('affected_component') or ''),
        str(item.get('title') or ''),
    ])
    return hashlib.sha256(raw.encode()).hexdigest()

def normalize_report(scanner: str, payload: dict[str, Any], asset_id: int, criticality: str) -> list[FindingDict]:
    scanner = scanner.lower()
    if scanner == 'trivy':
        return normalize_trivy(payload, asset_id, criticality)
    if scanner == 'grype':
        return normalize_grype(payload, asset_id, criticality)
    if scanner == 'syft':
        return normalize_syft(payload, asset_id, criticality)
    if scanner == 'zap':
        return normalize_zap(payload, asset_id, criticality)
    if scanner == 'openvas':
        return normalize_openvas(payload, asset_id, criticality)
    return []

def finalize(asset_id: int, scanner: str, criticality: str, item: FindingDict) -> FindingDict:
    sev = normalize_severity(item.get('severity_original') or item.get('severity_normalized'))
    cvss = item.get('cvss_score')
    item['severity_normalized'] = sev
    item['risk_score'] = risk_score(sev, criticality, cvss)
    item['dedup_key'] = make_dedup_key(asset_id, scanner, item)
    return item

def normalize_trivy(payload: dict[str, Any], asset_id: int, criticality: str) -> list[FindingDict]:
    findings: list[FindingDict] = []
    for result in payload.get('Results', []):
        target = result.get('Target')
        for v in result.get('Vulnerabilities', []) or []:
            cvss = None
            for vendor_data in (v.get('CVSS') or {}).values():
                if isinstance(vendor_data, dict) and vendor_data.get('V3Score'):
                    cvss = float(vendor_data.get('V3Score'))
                    break
            fixed = ', '.join(v.get('FixedVersion', '').split()) if v.get('FixedVersion') else None
            item = {
                'scanner': 'trivy',
                'finding_type': 'container_vulnerability',
                'title': f"{v.get('VulnerabilityID', 'Vulnerability')} in {v.get('PkgName', 'package')}",
                'description': v.get('Description') or v.get('Title'),
                'severity_original': v.get('Severity', 'UNKNOWN'),
                'cve': v.get('VulnerabilityID'),
                'cvss_score': cvss,
                'package_name': v.get('PkgName'),
                'installed_version': v.get('InstalledVersion'),
                'fixed_version': fixed,
                'affected_component': target,
                'evidence': f"{target}::{v.get('PkgName')} {v.get('InstalledVersion')}",
                'recommendation': f"Upgrade {v.get('PkgName')} to {fixed}" if fixed else 'Review vendor advisory and upgrade package if a fixed version is available.',
            }
            findings.append(finalize(asset_id, 'trivy', criticality, item))
        for s in result.get('Secrets', []) or []:
            item = {
                'scanner': 'trivy',
                'finding_type': 'secret_exposure',
                'title': s.get('Title') or 'Potential secret detected',
                'description': s.get('RuleID'),
                'severity_original': s.get('Severity', 'HIGH'),
                'affected_component': target,
                'evidence': s.get('Match') or str(s.get('StartLine')),
                'recommendation': 'Remove secret from source and rotate the exposed credential.',
            }
            findings.append(finalize(asset_id, 'trivy', criticality, item))
        for m in result.get('Misconfigurations', []) or []:
            item = {
                'scanner': 'trivy',
                'finding_type': 'iac_misconfiguration',
                'title': m.get('Title') or m.get('ID') or 'Misconfiguration',
                'description': m.get('Description'),
                'severity_original': m.get('Severity', 'MEDIUM'),
                'affected_component': target,
                'evidence': m.get('Message') or m.get('CauseMetadata', {}).get('Resource'),
                'recommendation': m.get('Resolution') or 'Review IaC misconfiguration and apply hardening recommendation.',
            }
            findings.append(finalize(asset_id, 'trivy', criticality, item))
    return findings

def normalize_grype(payload: dict[str, Any], asset_id: int, criticality: str) -> list[FindingDict]:
    findings: list[FindingDict] = []
    for match in payload.get('matches', []) or []:
        vuln = match.get('vulnerability') or {}
        artifact = match.get('artifact') or {}
        fixed_versions = vuln.get('fix', {}).get('versions') or []
        fixed = ', '.join(fixed_versions) if fixed_versions else None
        cvss = None
        for metric in vuln.get('cvss', []) or []:
            metrics = metric.get('metrics') or {}
            if metrics.get('baseScore'):
                cvss = float(metrics.get('baseScore'))
                break
        item = {
            'scanner': 'grype',
            'finding_type': 'dependency_vulnerability',
            'title': f"{vuln.get('id', 'Vulnerability')} in {artifact.get('name', 'package')}",
            'description': vuln.get('description'),
            'severity_original': vuln.get('severity', 'UNKNOWN'),
            'cve': vuln.get('id'),
            'cvss_score': cvss,
            'package_name': artifact.get('name'),
            'installed_version': artifact.get('version'),
            'fixed_version': fixed,
            'affected_component': artifact.get('locations', [{}])[0].get('path') if artifact.get('locations') else artifact.get('type'),
            'evidence': f"{artifact.get('name')} {artifact.get('version')}",
            'recommendation': f"Upgrade {artifact.get('name')} to {fixed}" if fixed else 'Review advisory and upgrade package.',
        }
        findings.append(finalize(asset_id, 'grype', criticality, item))
    return findings

def normalize_syft(payload: dict[str, Any], asset_id: int, criticality: str) -> list[FindingDict]:
    # SBOM is not a vulnerability by itself. Create informational component records for dashboard evidence.
    findings: list[FindingDict] = []
    artifacts = payload.get('artifacts') or payload.get('components') or []
    for artifact in artifacts[:25]:
        name = artifact.get('name')
        version = artifact.get('version')
        if not name:
            continue
        item = {
            'scanner': 'syft',
            'finding_type': 'sbom_component',
            'title': f"SBOM component: {name}",
            'description': 'Software component identified in SBOM.',
            'severity_original': 'INFO',
            'package_name': name,
            'installed_version': version,
            'affected_component': artifact.get('type') or artifact.get('purl'),
            'evidence': artifact.get('purl') or f"{name} {version}",
            'recommendation': 'Use SBOM as evidence for supply chain inventory and vulnerability correlation.',
        }
        findings.append(finalize(asset_id, 'syft', criticality, item))
    return findings

def normalize_zap(payload: dict[str, Any], asset_id: int, criticality: str) -> list[FindingDict]:
    findings: list[FindingDict] = []
    for site in payload.get('site', []) or []:
        site_name = site.get('@name') or site.get('name')
        for alert in site.get('alerts', []) or []:
            instances = alert.get('instances') or [{}]
            risk = alert.get('riskdesc') or alert.get('riskcode') or alert.get('risk') or 'INFO'
            if isinstance(risk, str) and 'High' in risk:
                sev = 'HIGH'
            elif isinstance(risk, str) and 'Medium' in risk:
                sev = 'MEDIUM'
            elif isinstance(risk, str) and 'Low' in risk:
                sev = 'LOW'
            else:
                sev = 'INFO'
            inst = instances[0] if instances else {}
            item = {
                'scanner': 'zap',
                'finding_type': 'web_vulnerability',
                'title': alert.get('alert') or alert.get('name') or 'ZAP finding',
                'description': alert.get('desc'),
                'severity_original': sev,
                'cwe': f"CWE-{alert.get('cweid')}" if alert.get('cweid') and str(alert.get('cweid')) != '0' else None,
                'affected_component': inst.get('uri') or site_name,
                'evidence': inst.get('evidence') or inst.get('param') or site_name,
                'recommendation': alert.get('solution') or 'Review web/API finding and apply OWASP recommendation.',
            }
            findings.append(finalize(asset_id, 'zap', criticality, item))
    return findings

def normalize_openvas(payload: dict[str, Any], asset_id: int, criticality: str) -> list[FindingDict]:
    findings: list[FindingDict] = []
    for v in payload.get('results', []) or []:
        item = {
            'scanner': 'openvas',
            'finding_type': 'host_vulnerability',
            'title': v.get('name') or 'OpenVAS finding',
            'description': v.get('description'),
            'severity_original': v.get('severity_label') or v.get('threat') or 'MEDIUM',
            'cve': v.get('cve'),
            'cvss_score': float(v['cvss']) if v.get('cvss') else None,
            'affected_component': f"{v.get('host')}:{v.get('port')}" if v.get('port') else v.get('host'),
            'evidence': v.get('evidence') or v.get('nvt_oid'),
            'recommendation': v.get('solution') or 'Apply vendor patch or hardening recommendation and retest.',
        }
        findings.append(finalize(asset_id, 'openvas', criticality, item))
    return findings
