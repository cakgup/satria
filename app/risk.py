SEVERITY_SCORE = {
    'CRITICAL': 95,
    'Critical': 95,
    'HIGH': 80,
    'High': 80,
    'MEDIUM': 55,
    'Medium': 55,
    'LOW': 25,
    'Low': 25,
    'INFO': 5,
    'Informational': 5,
    'UNKNOWN': 3,
}

CRITICALITY_FACTOR = {
    'critical': 1.15,
    'high': 1.08,
    'medium': 1.0,
    'low': 0.85,
}

def normalize_severity(value: str | None) -> str:
    if not value:
        return 'Informational'
    v = value.upper()
    if v in {'CRITICAL'}:
        return 'Critical'
    if v in {'HIGH'}:
        return 'High'
    if v in {'MEDIUM', 'MODERATE'}:
        return 'Medium'
    if v in {'LOW'}:
        return 'Low'
    return 'Informational'

def risk_score(severity: str | None, criticality: str | None, cvss: float | None = None) -> int:
    normalized = normalize_severity(severity)
    base = SEVERITY_SCORE.get(normalized, 5)
    if cvss is not None:
        # Blend scanner severity with CVSS score.
        base = int((base * 0.65) + ((cvss * 10) * 0.35))
    factor = CRITICALITY_FACTOR.get((criticality or 'medium').lower(), 1.0)
    return max(0, min(100, int(base * factor)))
