import requests, re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

PAYLOAD = "1'"

ERROR_PATTERNS = re.compile(
    r"(SQL syntax.*MySQL|Warning.*mysql_|PostgreSQL.*ERROR|ODBC SQL Server Driver)", re.I
)

def _mutate(url: str, param: str, payload: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query)
    qs[param] = payload
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))

def test(url: str, parameter: str, headers=None, timeout=8.0):
    target = _mutate(url, parameter, PAYLOAD)
    try:
        r = requests.get(target, headers=headers, timeout=timeout, verify=False)
        vulnerable = bool(ERROR_PATTERNS.search(r.text))
    except Exception:
        vulnerable = False
    return {
        "url": url,
        "technique": "Error‑based",
        "parameter": parameter,
        "payload": PAYLOAD,
        "vulnerable": vulnerable,
        "severity": "Medium" if vulnerable else "None",
    }
