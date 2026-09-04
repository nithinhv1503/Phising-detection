/**
 * AI Phishing Sentinel - Blocked Interstitial Logic
 */

document.addEventListener("DOMContentLoaded", () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = urlParams.get("url") || "Unknown Destination";
  const score = urlParams.get("score") || "98.5";
  const reason = urlParams.get("reason") || "Multiple phishing indicators identified by ML engine";

  document.getElementById("blockedUrlDisplay").textContent = targetUrl;
  document.getElementById("riskScoreDisplay").textContent = `${score}%`;
  document.getElementById("reasonDisplay").textContent = reason;

  // Back to Safety: Go back in history or redirect to Google
  document.getElementById("btnBackToSafety").addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "https://www.google.com";
    }
  });

  // Proceed anyway: Notify background to bypass and redirect to target URL
  document.getElementById("btnProceedAnyway").addEventListener("click", () => {
    if (confirm("WARNING: Proceeding to this site may compromise your personal data, passwords, or financial credentials. Are you sure?")) {
      chrome.runtime.sendMessage({ action: "BYPASS_URL", url: targetUrl }, () => {
        window.location.href = targetUrl;
      });
    }
  });

  // Toggle details section
  const btnToggle = document.getElementById("btnToggleDetails");
  const detailsContent = document.getElementById("detailsContent");
  btnToggle.addEventListener("click", () => {
    const isHidden = detailsContent.style.display === "none";
    detailsContent.style.display = isHidden ? "block" : "none";
    btnToggle.textContent = isHidden ? "Hide Diagnostics ▲" : "Details & Diagnostics ▼";
  });
});
