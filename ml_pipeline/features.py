"""
Feature Extraction Engine for Phishing Detection
Extracts 25+ lexical, structural, and content-based features from URLs and DOM.
"""

import re
import math
import ipaddress
from urllib.parse import urlparse
from collections import Counter
import tldextract


# Common URL shortening services
SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "cli.gs", "yfrog.com",
    "migre.me", "ff.im", "tiny.cc", "url4.eu", "twit.ac", "su.pr", "twurl.nl",
    "snipurl.com", "short.to", "ow.ly", "buff.ly", "adf.ly", "bitly.com",
    "cutt.ly", "rebrand.ly", "rb.gy", "shorturl.at"
}

# Suspicious keywords frequently used in phishing attacks
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "update", "security",
    "secure", "banking", "account", "confirm", "password", "credential",
    "wallet", "ebayisapi", "webscr", "paypal", "appleid", "support",
    "service", "recover", "authenticate", "auth", "token", "billing",
    "invoice", "claim", "prize", "suspended", "limited"
]

# Sensitive TLDs often abused for free or cheap phishing registration
SUSPICIOUS_TLDS = {"xyz", "top", "work", "click", "loan", "fit", "gq", "cf", "ga", "ml", "tk", "buzz", "icu", "club"}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string to measure character randomness."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def is_ip_address(domain: str) -> int:
    """Check if the domain is a raw IPv4 or IPv6 address."""
    if not domain:
        return 0
    clean_domain = str(domain).split(":")[0].strip("[]").strip()
    try:
        ipaddress.ip_address(clean_domain)
        return 1
    except Exception:
        return 0


def count_subdomains(extracted_domain) -> int:
    """Count subdomains using tldextract."""
    if not extracted_domain or not getattr(extracted_domain, "subdomain", None):
        return 0
    return len(extracted_domain.subdomain.split("."))


def extract_url_features(url: str) -> dict:
    """
    Extract comprehensive lexical and structural features from a single URL.
    Returns a dictionary of numerical and categorical feature flags.
    """
    if not url:
        url = ""
    
    # Ensure scheme for proper parsing
    normalized_url = url.strip()
    if not re.match(r"^https?://", normalized_url, re.IGNORECASE):
        normalized_url = "http://" + normalized_url

    try:
        parsed = urlparse(normalized_url)
        hostname = (parsed.hostname or "")
        path = (parsed.path or "")
        query = (parsed.query or "")
        parsed_port = parsed.port
        parsed_scheme = (parsed.scheme or "http")
    except Exception:
        parsed = None
        hostname = ""
        path = ""
        query = ""
        parsed_port = None
        parsed_scheme = "http"

    try:
        ext = tldextract.extract(normalized_url)
    except Exception:
        # Fallback dummy object
        class DummyExt:
            subdomain = ""
            domain = ""
            suffix = ""
        ext = DummyExt()
    
    full_url = normalized_url

    # Feature 1: Length metrics
    url_len = len(full_url)
    domain_len = len(hostname)
    path_len = len(path)

    # Feature 2: Character counts
    num_dots = full_url.count(".")
    num_hyphens = full_url.count("-")
    num_at = full_url.count("@")
    num_question = full_url.count("?")
    num_equal = full_url.count("=")
    num_slash = full_url.count("/")
    num_percent = full_url.count("%")
    num_ampersand = full_url.count("&")
    
    # Feature 3: Digits analysis
    num_digits = sum(c.isdigit() for c in full_url)
    digit_ratio = round(num_digits / max(1, url_len), 4)

    # Feature 4: IP address detection
    has_ip = is_ip_address(hostname) if hostname else 0

    # Feature 5: URL Shortener detection
    base_domain = f"{ext.domain}.{ext.suffix}".lower()
    is_shortened = 1 if (base_domain in SHORTENERS or hostname.lower() in SHORTENERS) else 0

    # Feature 6: Subdomain structure
    num_subdomains = count_subdomains(ext)
    
    # Feature 7: Suspicious Keywords Count
    lower_url = full_url.lower()
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower_url)

    # Feature 8: HTTPS and Security heuristics
    is_https = 1 if parsed_scheme.lower() == "https" else 0
    has_port = 1 if parsed_port is not None and parsed_port not in (80, 443) else 0
    
    # Feature 9: Prefix/Suffix '-' in domain name (common typosquatting trick)
    prefix_suffix = 1 if "-" in ext.domain else 0

    # Feature 10: Double slash redirect trick in path
    has_double_slash = 1 if "//" in path else 0

    # Feature 11: Shannon Entropy
    entropy = calculate_entropy(full_url)

    # Feature 12: Suspicious TLD
    is_suspicious_tld = 1 if ext.suffix.lower() in SUSPICIOUS_TLDS else 0

    # Feature 13: Brand spoofing (e.g. 'paypal' in subdomain or path, but not registered domain)
    has_brand_spoofing = 0
    for brand in ["paypal", "apple", "google", "microsoft", "netflix", "amazon", "chase", "bankofamerica", "facebook", "instagram"]:
        if brand in lower_url and brand != ext.domain.lower():
            has_brand_spoofing = 1
            break

    # Feature 14: TLD inside subdomain (e.g., login.paypal.com.phishingsite.com)
    tld_in_subdomain = 1 if any(tld in ext.subdomain.lower() for tld in [".com", ".net", ".org", ".gov"]) else 0

    # Feature 15: Subdomain length
    subdomain_len = len(ext.subdomain)

    # Feature 16: Number of digits in hostname
    digit_count_in_host = sum(c.isdigit() for c in hostname)

    # Feature 17: Longest token in URL path/query
    tokens = re.split(r"[/._?=&-]", full_url)
    longest_token_len = max([len(t) for t in tokens if t], default=0)

    # Feature 18: Sensitive parameter count
    sensitive_params = ["cmd=", "token=", "auth=", "dispatch=", "email=", "id=", "session=", "key=", "ref=", "url="]
    num_sensitive_params = sum(1 for p in sensitive_params if p in lower_url)

    return {
        "url_length": url_len,
        "domain_length": domain_len,
        "path_length": path_len,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_at": num_at,
        "num_question": num_question,
        "num_equal": num_equal,
        "num_slash": num_slash,
        "num_percent": num_percent,
        "num_ampersand": num_ampersand,
        "num_digits": num_digits,
        "digit_ratio": digit_ratio,
        "has_ip": has_ip,
        "is_shortened": is_shortened,
        "num_subdomains": num_subdomains,
        "subdomain_len": subdomain_len,
        "digit_count_in_host": digit_count_in_host,
        "longest_token_len": longest_token_len,
        "num_sensitive_params": num_sensitive_params,
        "keyword_count": keyword_count,
        "is_https": is_https,
        "has_port": has_port,
        "prefix_suffix": prefix_suffix,
        "has_double_slash": has_double_slash,
        "entropy": entropy,
        "is_suspicious_tld": is_suspicious_tld,
        "has_brand_spoofing": has_brand_spoofing,
        "tld_in_subdomain": tld_in_subdomain
    }


def extract_dom_features(html_content: str, current_domain: str = "") -> dict:
    """
    Extract content/DOM features from HTML if available.
    """
    if not html_content:
        return {
            "num_forms": 0,
            "has_password_field": 0,
            "insecure_form_action": 0,
            "external_link_ratio": 0.0,
            "num_iframes": 0,
            "has_hidden_inputs": 0
        }

    from bs4 import BeautifulSoup
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        
        forms = soup.find_all("form")
        num_forms = len(forms)
        
        password_inputs = soup.find_all("input", {"type": re.compile(r"password", re.I)})
        has_password_field = 1 if len(password_inputs) > 0 else 0
        
        insecure_form_action = 0
        for form in forms:
            action = form.get("action", "").strip()
            if action.startswith("http://") or action == "" or action == "#" or "about:blank" in action:
                insecure_form_action = 1
                break
                
        # Link analysis
        all_links = soup.find_all("a", href=True)
        external_count = 0
        for link in all_links:
            href = link["href"]
            if href.startswith("http") and current_domain and current_domain not in href:
                external_count += 1
        
        external_link_ratio = round(external_count / max(1, len(all_links)), 4)
        num_iframes = len(soup.find_all("iframe"))
        
        hidden_inputs = soup.find_all("input", {"type": re.compile(r"hidden", re.I)})
        has_hidden_inputs = 1 if len(hidden_inputs) > 0 else 0
        
        return {
            "num_forms": num_forms,
            "has_password_field": has_password_field,
            "insecure_form_action": insecure_form_action,
            "external_link_ratio": external_link_ratio,
            "num_iframes": num_iframes,
            "has_hidden_inputs": has_hidden_inputs
        }
    except Exception:
        return {
            "num_forms": 0,
            "has_password_field": 0,
            "insecure_form_action": 0,
            "external_link_ratio": 0.0,
            "num_iframes": 0,
            "has_hidden_inputs": 0
        }


# Ordered list of URL feature keys used for consistent vectorization
FEATURE_COLUMNS = [
    "url_length",
    "domain_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_at",
    "num_question",
    "num_equal",
    "num_slash",
    "num_percent",
    "num_ampersand",
    "num_digits",
    "digit_ratio",
    "has_ip",
    "is_shortened",
    "num_subdomains",
    "subdomain_len",
    "digit_count_in_host",
    "longest_token_len",
    "num_sensitive_params",
    "keyword_count",
    "is_https",
    "has_port",
    "prefix_suffix",
    "has_double_slash",
    "entropy",
    "is_suspicious_tld",
    "has_brand_spoofing",
    "tld_in_subdomain"
]


def url_to_feature_vector(url: str) -> list:
    """Convert URL directly to an ordered numerical feature vector."""
    feats = extract_url_features(url)
    return [feats[col] for col in FEATURE_COLUMNS]
