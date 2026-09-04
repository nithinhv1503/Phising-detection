"""
Dataset Builder & Synthesizer for Phishing vs. Legitimate URLs.
Generates balanced, representative benchmark datasets with realistic phishing attack vectors
and legitimate domain structures. Supports importing live OpenPhish feeds.
"""

import os
import random
import pandas as pd
import requests
from ml_pipeline.features import extract_url_features, FEATURE_COLUMNS

# Verified Legitimate Domains across multiple sectors (Tech, Banking, Education, Gov, E-commerce, Media)
LEGITIMATE_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "yahoo.com",
    "amazon.com", "twitter.com", "instagram.com", "linkedin.com", "reddit.com",
    "netflix.com", "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "paypal.com", "citi.com",
    "harvard.edu", "mit.edu", "stanford.edu", "ox.ac.uk", "cam.ac.uk",
    "nih.gov", "nasa.gov", "irs.gov", "who.int", "un.org",
    "nytimes.com", "bbc.com", "cnn.com", "reuters.com", "theguardian.com",
    "spotify.com", "zoom.us", "dropbox.com", "adobe.com", "salesforce.com",
    "ebay.com", "walmart.com", "target.com", "aliexpress.com", "shopify.com",
    "medium.com", "quora.com", "twitch.tv", "vimeo.com", "cloudflare.com",
    "aws.amazon.com", "docs.python.org", "developer.mozilla.org", "pypi.org", "kaggle.com"
]

LEGITIMATE_PATHS = [
    "", "/", "/about", "/contact", "/terms", "/privacy", "/help", "/faq",
    "/products/item-129481", "/news/2026/08/article", "/user/profile/settings",
    "/dashboard/analytics", "/docs/v2/getting-started", "/category/technology",
    "/search?q=machine+learning&page=2", "/api/v1/status", "/resources/whitepapers"
]

# Common Phishing Generation Templates
PHISHING_PATTERNS = [
    # IP address hosts
    "http://192.168.1.105/bank/login.php?cmd=verify",
    "http://45.142.214.7/paypal/update_account.html",
    "http://185.220.101.5/netflix/billing/confirm_payment",
    "http://103.251.167.22:8080/secure/chase-auth",
    "http://91.240.118.12/appleid/recover-password.php",
    "http://178.62.204.111/binance-login/auth.html",
    "http://5.188.62.88:8888/wellsfargo/verification",
    
    # Brand spoofing subdomains & TLD in subdomain
    "http://paypal.com.verify-billing-center.xyz/login.php",
    "http://appleid.apple.com.account-recovery.top/verify",
    "http://chase.com.security-alert-update.buzz/auth",
    "http://netflix.com.payment-declined.club/re-activate",
    "http://microsoft.com.online-auth-portal.icu/signin",
    "http://accounts.google.com.security-checkpoint.work/service",
    "http://amazon.com.order-verification-alert.top/claim",
    "http://bankofamerica.com.session-expire.click/customer",
    "http://wellsfargo.com.online-secure-access.loan/portal",
    "http://instagram.com.copyright-appeal-center.xyz/confirm",
    "http://support.binance.com.wallet-connect.top/auth",
    
    # Suspicious keywords & Typosquatting / Hyphen overload
    "http://secure-login-account-update-verify-chase.com/login",
    "http://paypaI-security-verification-alert-2026.net/login.php",
    "http://netfllix-billing-update-center.com/signin",
    "http://micros0ft-security-center-support.org/login",
    "http://amaz0n-prime-reward-claim-center.xyz/claim",
    "http://app1e-id-locked-account-restore.info/verify.php",
    "http://faceb00k-security-checkpoint-appeal.cc/login",
    "http://secure-banking-portal-auth-id98234.biz/session",
    "http://verify-my-account-status-urgent.online/reauth",
    
    # Shortener and redirect trick
    "http://bit.ly/3xSecuredBankLoginRedirect",
    "http://tinyurl.com/paypal-account-resolve-suspended",
    "http://cutt.ly/netflix-membership-expired-action",
    "http://rb.gy/apple-security-id-alert-login",
    
    # Obfuscation & Path tricks
    "http://legit-site.com//www.paypal.com/webscr.php?cmd=_login-run",
    "http://university-portal.edu@malicious-phish-domain.com/login",
    "http://portal.com:8443/chase/bank/auth?token=928374982374982374982374",
    "http://secure.account.update.verify.auth.portal.xyz/cgi-bin/webscr"
]


def generate_synthetic_dataset(n_samples: int = 4000) -> pd.DataFrame:
    """
    Generate a diverse, high-quality balanced dataset of legitimate and phishing URLs.
    Includes edge cases, parameter pollution, IP addresses, homoglyphs, and realistic traffic.
    """
    data = []
    
    # 1. Generate Legitimate URLs (Label: 0)
    for _ in range(n_samples // 2):
        domain = random.choice(LEGITIMATE_DOMAINS)
        path = random.choice(LEGITIMATE_PATHS)
        scheme = "https://" if random.random() > 0.05 else "http://"
        
        # Subdomains on legit sites (e.g. docs.python.org, mail.google.com)
        if random.random() < 0.35 and not domain.startswith("aws.") and not domain.startswith("docs."):
            sub = random.choice(["www", "app", "login", "portal", "my", "mail", "help", "blog", "dev", "api"])
            url = f"{scheme}{sub}.{domain}{path}"
        else:
            url = f"{scheme}{domain}{path}"
            
        data.append({"url": url, "label": 0})

    # 2. Base Phishing Seed Patterns
    for url in PHISHING_PATTERNS:
        data.append({"url": url, "label": 1})

    # 3. Generate Variational Phishing URLs (Label: 1)
    brands = ["paypal", "apple", "netflix", "chase", "amazon", "wellsfargo", "microsoft", "google", "binance", "instagram", "facebook", "bankofamerica"]
    tlds = ["xyz", "top", "buzz", "club", "work", "click", "icu", "loan", "tk", "info", "online", "live"]
    phish_actions = ["verify", "security-update", "confirm-identity", "billing-resolve", "account-alert", "session-unlock", "suspended-notice", "auth-portal"]
    
    needed_phish = (n_samples // 2) - len(PHISHING_PATTERNS)
    for _ in range(max(0, needed_phish)):
        generator_type = random.choice(["ip", "subdomain_spoof", "hyphen_keyword", "shortener", "double_slash", "long_token"])
        
        brand = random.choice(brands)
        action = random.choice(phish_actions)
        tld = random.choice(tlds)
        
        if generator_type == "ip":
            ip = f"{random.randint(11, 215)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            port = f":{random.choice([8080, 8888, 4444, 3000])}" if random.random() < 0.4 else ""
            url = f"http://{ip}{port}/{brand}/{action}.php?id={random.randint(10000, 99999)}"
            
        elif generator_type == "subdomain_spoof":
            url = f"http://{brand}.com.{action}-{random.randint(100, 999)}.{tld}/login?ref={random.randint(1000, 9999)}"
            
        elif generator_type == "hyphen_keyword":
            typo_brand = brand.replace("o", "0").replace("l", "1").replace("e", "3") if random.random() < 0.4 else brand
            url = f"http://secure-{typo_brand}-{action}-center.{tld}/signin.html"
            
        elif generator_type == "shortener":
            shortener = random.choice(["bit.ly", "tinyurl.com", "cutt.ly", "rb.gy"])
            token = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=8))
            url = f"http://{shortener}/{token}-{brand}-alert"
            
        elif generator_type == "double_slash":
            url = f"http://free-host-{random.randint(10,99)}.{tld}//www.{brand}.com/update?token={random.randint(100000, 999999)}"
            
        else: # long_token & obfuscated query
            long_param = "".join(random.choices("abcdef0123456789", k=48))
            url = f"http://portal-{brand}-verify.{tld}/index.php?token={long_param}&auth=required"
            
        data.append({"url": url, "label": 1})

    df = pd.DataFrame(data)
    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df


def fetch_openphish_feed(limit: int = 500) -> list:
    """Attempt to fetch active live community phishing URLs from OpenPhish (free)."""
    try:
        url = "https://openphish.com/feed.txt"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            urls = [line.strip() for line in resp.text.strip().split("\n") if line.strip()][:limit]
            return urls
    except Exception:
        pass
    return []


def build_and_save_dataset(output_path: str = "ml_pipeline/data/phishing_dataset.csv", n_samples: int = 5000):
    """Generate or download datasets, extract feature matrix, and persist to CSV."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    print(f"[*] Generating balanced benchmark dataset with {n_samples} samples...")
    
    df = generate_synthetic_dataset(n_samples=n_samples)
    
    # Try appending live OpenPhish URLs if accessible
    live_phish = fetch_openphish_feed(limit=300)
    if live_phish:
        print(f"[*] Ingested {len(live_phish)} live community phishing URLs from OpenPhish.")
        live_df = pd.DataFrame([{"url": u, "label": 1} for u in live_phish])
        df = pd.concat([df, live_df], ignore_index=True).drop_duplicates(subset=["url"])
        
    print(f"[*] Total dataset size: {len(df)} (Phishing: {(df['label'] == 1).sum()}, Legitimate: {(df['label'] == 0).sum()})")
    
    # Extract feature representations
    print("[*] Extracting 25+ features for all URLs...")
    feature_rows = []
    for idx, url in enumerate(df["url"]):
        feats = extract_url_features(url)
        feats["label"] = df.iloc[idx]["label"]
        feats["url"] = url
        feature_rows.append(feats)
        
    feature_df = pd.DataFrame(feature_rows)
    feature_df.to_csv(output_path, index=False)
    print(f"[+] Dataset saved successfully to: {output_path}")
    return feature_df


if __name__ == "__main__":
    build_and_save_dataset()
