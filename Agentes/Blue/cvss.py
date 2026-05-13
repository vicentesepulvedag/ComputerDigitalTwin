_CVSS_MAP = {
    "AV": {
        "NETWORK": 0.85,
        "ADJACENT": 0.62,
        "LOCAL": 0.55,
        "PHYSICAL": 0.2,
        "N": 0.85,
        "A": 0.62,
        "L": 0.55,
        "P": 0.2,
    },
    "AC": {"LOW": 0.77, "HIGH": 0.44, "L": 0.77, "H": 0.44},
    "PR": {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27, "N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"NONE": 0.85, "REQUIRED": 0.62, "N": 0.85, "R": 0.62},
    "C": {"HIGH": 0.56, "LOW": 0.22, "NONE": 0.0, "H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"HIGH": 0.56, "LOW": 0.22, "NONE": 0.0, "H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"HIGH": 0.56, "LOW": 0.22, "NONE": 0.0, "H": 0.56, "L": 0.22, "N": 0.0},
}


def _cvss_metric(key: str, value) -> float:
    try:
        return float(value)
    except (ValueError, TypeError):
        mapping = _CVSS_MAP.get(key, {})
        return mapping.get(str(value).upper().strip(), 0.0)


def calcular_cvss(metrics: dict) -> float:
    try:
        C = _cvss_metric("C", metrics.get("C", 0.0))
        I = _cvss_metric("I", metrics.get("I", 0.0))
        A = _cvss_metric("A", metrics.get("A", 0.0))
        AV = _cvss_metric("AV", metrics.get("AV", 0.0))
        AC = _cvss_metric("AC", metrics.get("AC", 0.0))
        PR = _cvss_metric("PR", metrics.get("PR", 0.0))
        UI = _cvss_metric("UI", metrics.get("UI", 0.0))
    except (ValueError, TypeError):
        return 0.0

    impact = 1 - (1 - C) * (1 - I) * (1 - A)
    impact_score = 6.42 * impact
    exploitability = 8.22 * AV * AC * PR * UI

    base_score = min(impact_score + exploitability, 10)
    return round(base_score, 2)


def clasificar(score: float) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"
