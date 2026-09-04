"""
Threat Intelligence Feed Synchronizer.
Periodically fetches active zero-day phishing feeds from free open feeds (OpenPhish / PhishTank)
and updates the local Threat Intelligence Cache.
"""

import time
import requests
from backend.threat_intel import threat_intel

OPENPHISH_URL = "https://openphish.com/feed.txt"


def sync_openphish(limit: int = 500) -> int:
    """Sync active phishing URLs from OpenPhish community feed."""
    print("[*] Fetching latest active threat indicators from OpenPhish...")
    try:
        resp = requests.get(OPENPHISH_URL, timeout=8)
        if resp.status_code == 200:
            urls = [line.strip() for line in resp.text.strip().split("\n") if line.strip()][:limit]
            added_count = 0
            for u in urls:
                threat_intel.add_to_blocklist(u)
                added_count += 1
            print(f"[+] Successfully synchronized {added_count} active threat URLs into Blocklist.")
            return added_count
        else:
            print(f"[-] OpenPhish returned status {resp.status_code}")
    except Exception as e:
        print(f"[-] Error fetching threat feed: {e}")
    return 0


def run_sync():
    print("=== THREAT INTELLIGENCE FEED SYNCHRONIZATION ===")
    count = sync_openphish(limit=500)
    summary = threat_intel.check_reputation("http://paypal.com.verify-billing-center.xyz")
    print(f"[*] Threat Intel Status Sample: {summary}")
    print("[+] Threat Intel synchronization complete.")


if __name__ == "__main__":
    run_sync()
