/**
 * AI Phishing Sentinel - Popup UI Logic
 */

document.addEventListener("DOMContentLoaded", async () => {
  const siteHost = document.getElementById("siteHost");
  const gaugeCircle = document.getElementById("gaugeCircle");
  const gaugeVal = document.getElementById("gaugeVal");
  const verdictTitle = document.getElementById("verdictTitle");
  const statusPill = document.getElementById("statusPill");
  const indicatorsList = document.getElementById("indicatorsList");
  const btnWhitelist = document.getElementById("btnWhitelist");
  const btnReportPhish = document.getElementById("btnReportPhish");

  let currentTabUrl = "";

  // Get current active tab
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    if (!tabs || tabs.length === 0 || !tabs[0].url) {
      siteHost.textContent = "No active URL";
      return;
    }

    currentTabUrl = tabs[0].url;
    try {
      const parsed = new URL(currentTabUrl);
      siteHost.textContent = parsed.hostname;
    } catch {
      siteHost.textContent = currentTabUrl;
    }

    // Ask background script for the evaluation result
    chrome.runtime.sendMessage({ action: "GET_CURRENT_TAB_RESULT" }, (result) => {
      renderResult(result);
    });
  });

  function renderResult(res) {
    if (!res) {
      statusPill.textContent = "SAFE";
      statusPill.style.color = "#00e676";
      verdictTitle.textContent = "Normal Page";
      gaugeVal.textContent = "0%";
      return;
    }

    const score = Math.round(Number(res.risk_score) || 0);
    gaugeVal.textContent = `${score}%`;

    if (res.verdict === "PHISHING") {
      gaugeCircle.style.borderColor = "#ff3366";
      gaugeVal.style.color = "#ff3366";
      verdictTitle.textContent = "PHISHING SITE";
      verdictTitle.style.color = "#ff3366";
      statusPill.textContent = "DANGEROUS";
      statusPill.style.color = "#ff3366";
      statusPill.style.background = "rgba(255, 51, 102, 0.15)";
    } else if (res.verdict === "SUSPICIOUS") {
      gaugeCircle.style.borderColor = "#ffab00";
      gaugeVal.style.color = "#ffab00";
      verdictTitle.textContent = "SUSPICIOUS";
      verdictTitle.style.color = "#ffab00";
      statusPill.textContent = "CAUTION";
      statusPill.style.color = "#ffab00";
      statusPill.style.background = "rgba(255, 171, 0, 0.15)";
    } else {
      gaugeCircle.style.borderColor = "#00e676";
      gaugeVal.style.color = "#00e676";
      verdictTitle.textContent = "SAFE SITE";
      verdictTitle.style.color = "#00e676";
      statusPill.textContent = "PROTECTED";
      statusPill.style.color = "#00e676";
      statusPill.style.background = "rgba(0, 230, 118, 0.15)";
    }

    // Render risk factor list
    indicatorsList.innerHTML = "";
    if (res.risk_factors && res.risk_factors.length > 0) {
      res.risk_factors.forEach((f) => {
        const div = document.createElement("div");
        div.className = "indicator-row";
        div.textContent = `• ${f.factor}`;
        indicatorsList.appendChild(div);
      });
    } else {
      indicatorsList.innerHTML = `<div class="clean-msg">✓ No phishing patterns detected</div>`;
    }
  }

  // Whitelist Button
  btnWhitelist.addEventListener("click", async () => {
    if (!currentTabUrl) return;
    try {
      const domain = new URL(currentTabUrl).hostname;
      await fetch("http://localhost:8000/api/v1/threat-intel/whitelist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ entry: domain })
      });
      alert(`Whitelisted '${domain}'! Reload page.`);
    } catch (e) {
      alert("Could not reach backend API.");
    }
  });

  // Report Phishing Button
  btnReportPhish.addEventListener("click", async () => {
    if (!currentTabUrl) return;
    try {
      await fetch("http://localhost:8000/api/v1/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: currentTabUrl,
          report_type: "phishing",
          comments: "Reported via extension popup"
        })
      });
      alert("Thank you! Phishing report submitted for review.");
    } catch (e) {
      alert("Could not reach backend API.");
    }
  });
});
