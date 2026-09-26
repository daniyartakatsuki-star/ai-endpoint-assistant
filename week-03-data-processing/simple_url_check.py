# simple_url_check.py — MVP heuristic + feed lookup for phishing URLs
import json
import os
import re
from urllib.parse import urlparse

def load_known_bad_domains(path="iocs_normalized.json"):
    """Loads domains from iocs_normalized.json, produced by
    filter_normalize_iocs.py (filtered + deduplicated URLhaus data).
    Falls back to a small sample set if that file isn't present yet
    (e.g. running this script before filter_normalize_iocs.py)."""
    if os.path.exists(path):
        with open(path) as f:
            data = json.load(f)
        return {record["domain"] for record in data if record.get("domain")}
    return {"example-phish.com", "secure-login-update.net"}  # offline fallback sample

KNOWN_BAD_DOMAINS = load_known_bad_domains()

def suspicious_score(url: str) -> float:
    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0]  # strip port to match iocs_normalized.json's domain format
    score = 0.0

    if domain in KNOWN_BAD_DOMAINS:
        score += 0.9
    if re.search(r"(login|verify|secure|update).{0,10}\.(net|xyz|top)", domain):
        score += 0.3
    if domain.count("-") >= 3:
        score += 0.2
    if len(domain) > 40:
        score += 0.1

    return min(score, 1.0)

def explain(url: str, score: float) -> str:
    if score >= 0.7:
        return f"⚠️ '{url}' looks like a phishing attempt — avoid entering any credentials."
    if score >= 0.3:
        return f"🟡 '{url}' has some suspicious traits — proceed with caution."
    return f"✅ '{url}' looks safe based on current checks."

if __name__ == "__main__":
    test_urls = [
        "http://example-phish.com/login",
        "https://secure-login-update.net/verify-account",
        "https://www.google.com",
    ]

    # The feed is live and changes constantly, so instead of hardcoding one
    # specific domain (which can disappear from the feed between runs), we
    # pick a real domain straight out of whatever KNOWN_BAD_DOMAINS currently
    # holds — this always tests against genuinely current, real data.
    FALLBACK_SAMPLE = {"example-phish.com", "secure-login-update.net"}
    real_domains = KNOWN_BAD_DOMAINS - FALLBACK_SAMPLE
    if real_domains:
        sample_real_domain = sorted(real_domains)[0]
        test_urls.insert(0, f"http://{sample_real_domain}/")
        print(f"(Loaded {len(KNOWN_BAD_DOMAINS)} real domains from iocs_normalized.json — testing against: {sample_real_domain})\n")
    else:
        print("(iocs_normalized.json not found — using offline fallback sample only)\n")

    for u in test_urls:
        s = suspicious_score(u)
        print(explain(u, s))
