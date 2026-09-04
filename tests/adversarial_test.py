"""
Adversarial Stress-Testing Suite for Phishing Detection System.
Tests system resilience against zero-day evasion techniques:
- Homoglyph & Typosquatting attacks (e.g. paypa1, micros0ft, goog1e)
- Deep Subdomain Chaining & TLD in Subdomain
- URL Shortener masquerading
- IP address evasion & non-standard port redirection
- Obfuscated query string and character encoding
"""

import time
from backend.predictor import predictor


ADVERSARIAL_TEST_CASES = [
    # Typosquatting & Character replacement
    {
        "category": "Typosquatting / Homoglyph",
        "url": "http://paypa1-security-verification-alert.com/login",
        "expected_risk": "HIGH"
    },
    {
        "category": "Brand Typosquatting",
        "url": "http://micros0ft-online-support-center.xyz/auth",
        "expected_risk": "HIGH"
    },
    {
        "category": "Lookalike Domain",
        "url": "http://netfllix-billing-update-urgent.info/reactivate",
        "expected_risk": "HIGH"
    },
    # Subdomain deception & TLD masking
    {
        "category": "TLD in Subdomain",
        "url": "http://accounts.google.com.security-checkpoint.work/service",
        "expected_risk": "HIGH"
    },
    {
        "category": "Deep Subdomain Nesting",
        "url": "http://chase.com.login.verify.account.status.buzz/auth",
        "expected_risk": "HIGH"
    },
    # IP Address & Non-standard Port
    {
        "category": "Raw IP Host with Port",
        "url": "http://185.220.101.5:8080/wellsfargo/verification.php",
        "expected_risk": "HIGH"
    },
    # Double Slash Redirect
    {
        "category": "Double Slash Path Trick",
        "url": "http://insecure-host.top//www.paypal.com/webscr.php",
        "expected_risk": "HIGH"
    },
    # Legitimate edge cases (False Positive Resistance)
    {
        "category": "Legitimate Cloud Subdomain",
        "url": "https://aws.amazon.com/solutions/case-studies",
        "expected_risk": "LOW"
    },
    {
        "category": "Legitimate Multi-tier Portal",
        "url": "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
        "expected_risk": "LOW"
    },
    {
        "category": "Legitimate Search Query",
        "url": "https://www.google.com/search?q=machine+learning+cybersecurity",
        "expected_risk": "LOW"
    }
]


def run_adversarial_benchmark():
    print("\n" + "=" * 80)
    print("=== ADVERSARIAL STRESS-TESTING & EVASION ROBUSTNESS BENCHMARK ===")
    print("=" * 80)
    print(f"{'Attack Category':<28} | {'Score':<7} | {'Verdict':<12} | {'Latency':<8} | {'Status'}")
    print("-" * 80)

    passed = 0
    total = len(ADVERSARIAL_TEST_CASES)

    for case in ADVERSARIAL_TEST_CASES:
        url = case["url"]
        expected = case["expected_risk"]
        cat = case["category"]

        res = predictor.predict(url)
        score = res["risk_score"]
        verdict = res["verdict"]
        latency = f"{res['latency_ms']}ms"

        # Check if classification matches expectation
        if expected == "HIGH" and verdict in ["PHISHING", "SUSPICIOUS"]:
            status = "[PASSED] BLOCKED"
            passed += 1
        elif expected == "LOW" and verdict == "LEGITIMATE":
            status = "[PASSED] ALLOWED"
            passed += 1
        else:
            status = "[FAILED] MISCLASSIFIED"

        print(f"{cat:<28} | {score:5.1f}%  | {verdict:<12} | {latency:<8} | {status}")

    print("=" * 80)
    success_rate = (passed / total) * 100
    print(f"[+] Adversarial Test Score: {passed}/{total} Passed ({success_rate:.1f}% Success Rate)")
    return success_rate


if __name__ == "__main__":
    run_adversarial_benchmark()
