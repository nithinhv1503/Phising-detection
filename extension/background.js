/**
 * AI Phishing Sentinel - Service Worker (Background Script)
 * Intercepts navigations, communicates with ML scoring API, and redirects to block screen.
 */

const API_BASE_URL = "http://localhost:8000/api/v1";
const SCORE_CACHE = new Map(); // In-memory URL cache for sub-millisecond repeated checks
const BYPASSED_URLS = new Set(); // Temporary session bypass set when user clicks "Proceed anyway"

// Listen for top-level navigation before page load
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only intercept main frame navigations
  if (details.frameId !== 0) return;
  const url = details.url;

  // Ignore internal browser schemes and the extension's own block screen
  if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("about:")) {
    return;
  }

  // Check if user explicitly chose to bypass for this session
  if (BYPASSED_URLS.has(url)) return;

  try {
    const result = await evaluateUrl(url);

    // Update Extension Badge
    updateBadge(details.tabId, result);

    // If Phishing detected with high confidence (risk >= 70%), redirect to block interstitial
    if (result && result.verdict === "PHISHING" && result.risk_score >= 70) {
      const blockedUrl = chrome.runtime.getURL(
        `blocked/blocked.html?url=${encodeURIComponent(url)}&score=${result.risk_score}&reason=${encodeURIComponent(
          result.reputation_reason || "AI Model detected high-confidence phishing indicators."
        )}`
      );
      chrome.tabs.update(details.tabId, { url: blockedUrl });
    }
  } catch (err) {
    console.error("[Sentinel] Error during navigation check:", err);
  }
});

// Evaluate URL against cache or API
async function evaluateUrl(url) {
  if (SCORE_CACHE.has(url)) {
    return SCORE_CACHE.get(url);
  }

  try {
    const response = await fetch(`${API_BASE_URL}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (response.ok) {
      const data = await response.json();
      SCORE_CACHE.set(url, data);
      return data;
    }
  } catch (e) {
    console.warn("[Sentinel] Could not reach detection backend:", e);
  }

  return { verdict: "LEGITIMATE", risk_score: 0, threat_intel_status: "unknown" };
}

// Update Extension Icon Badge
function updateBadge(tabId, result) {
  if (!result) return;

  if (result.verdict === "PHISHING") {
    chrome.action.setBadgeText({ tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#FF3366" });
  } else if (result.verdict === "SUSPICIOUS") {
    chrome.action.setBadgeText({ tabId, text: "WARN" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#FFAB00" });
  } else {
    chrome.action.setBadgeText({ tabId, text: "OK" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#00E676" });
  }
}

// Listen for messages from popup or blocked page
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "BYPASS_URL" && message.url) {
    BYPASSED_URLS.add(message.url);
    sendResponse({ status: "bypassed" });
  } else if (message.action === "GET_CURRENT_TAB_RESULT") {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (tabs.length > 0 && tabs[0].url) {
        const result = await evaluateUrl(tabs[0].url);
        sendResponse(result);
      } else {
        sendResponse(null);
      }
    });
    return true; // Keep channel open for async response
  }
});
