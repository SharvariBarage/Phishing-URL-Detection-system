
"""
Phishing URL Detection System
Educational cybersecurity project.
"""

from urllib.parse import urlparse
import re
import unittest

SUSPICIOUS_KEYWORDS = (
    "login", "verify", "update", "secure", "account", "banking",
    "password", "signin", "confirm", "wallet", "support"
)

SHORTENERS = (
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "ow.ly"
)


def analyze_url(url: str) -> dict:
    """Check a URL for basic warning signs."""
    raw = url.strip()

    if not raw:
        return {
            "url": raw,
            "risk": "Invalid",
            "score": 0,
            "findings": ["Please enter a URL."]
        }

    candidate = raw if "://" in raw else "http://" + raw
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()

    findings = []
    score = 0

    if parsed.scheme.lower() != "https":
        score += 1
        findings.append("URL does not use HTTPS.")

    if "@" in parsed.netloc:
        score += 2
        findings.append(
            "Contains '@' in the network location, "
            "which can disguise the destination."
        )

    if host and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 2
        findings.append(
            "Uses an IP address instead of a typical domain name."
        )

    if len(raw) > 75:
        score += 1
        findings.append("Unusually long URL.")

    if host.count("-") >= 2:
        score += 1
        findings.append("Domain contains multiple hyphens.")

    if host.startswith("xn--") or ".xn--" in host:
        score += 1
        findings.append(
            "Domain contains an internationalized/punycode label."
        )

    if any(
        shortener == host or host.endswith("." + shortener)
        for shortener in SHORTENERS
    ):
        score += 2
        findings.append(
            "Uses a URL-shortening service that hides the final destination."
        )

    matched = [
        word for word in SUSPICIOUS_KEYWORDS
        if word in raw.lower()
    ]

    if matched:
        score += 1
        findings.append(
            "Contains potentially deceptive keywords: "
            + ", ".join(matched) + "."
        )

    if score >= 4:
        risk = "High"
    elif score >= 2:
        risk = "Medium"
    else:
        risk = "Low"

    if not findings:
        findings.append(
            "No listed warning signs were detected by these basic checks."
        )

    findings.append(
        "This result is a heuristic estimate, not proof that a URL "
        "is safe or malicious."
    )

    return {
        "url": raw,
        "risk": risk,
        "score": score,
        "findings": findings
    }


# Tests previously stored in test_app.py
class TestURLAnalyzer(unittest.TestCase):

    def test_empty_url(self):
        result = analyze_url("")
        self.assertEqual(result["risk"], "Invalid")

    def test_https_example_is_low(self):
        result = analyze_url("https://www.example.com")
        self.assertEqual(result["risk"], "Low")

    def test_ip_and_http_are_flagged(self):
        result = analyze_url("http://192.0.2.10/login")
        self.assertGreaterEqual(result["score"], 4)
        self.assertEqual(result["risk"], "High")

    def test_shortener_is_flagged(self):
        result = analyze_url("http://bit.ly/verify-account")
        self.assertGreaterEqual(result["score"], 4)


def main():
    print("=" * 56)
    print("       PHISHING URL DETECTION SYSTEM")
    print("   Educational heuristic checker - do not trust blindly")
    print("=" * 56)

    while True:
        url = input(
            "\nEnter a URL (or type 'exit' to quit): "
        ).strip()

        if url.lower() == "exit":
            print("Goodbye. Stay safe online!")
            break

        result = analyze_url(url)

        print(
            f"\nRisk level: {result['risk']} "
            f"(score: {result['score']})"
        )

        for item in result["findings"]:
            print(f"- {item}")


if __name__ == "__main__":
    main()