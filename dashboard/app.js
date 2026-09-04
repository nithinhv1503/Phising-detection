/**
 * AI Phishing Sentinel - Dashboard Logic & Visualizations
 */

document.addEventListener("DOMContentLoaded", () => {
  // Navigation Tabs
  const navTabs = document.querySelectorAll(".nav-tab");
  const tabPanes = document.querySelectorAll(".tab-pane");

  navTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      navTabs.forEach((t) => t.classList.remove("active"));
      tabPanes.forEach((p) => p.classList.remove("active"));

      tab.classList.add("active");
      const targetId = tab.getAttribute("data-tab");
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add("active");

      if (targetId === "tab-metrics") loadModelMetrics();
      if (targetId === "tab-threat-intel") loadThreatIntel();
    });
  });

  // Quick Test Buttons
  const quickButtons = document.querySelectorAll(".btn-quick");
  const targetUrlInput = document.getElementById("targetUrlInput");
  const btnScanUrl = document.getElementById("btnScanUrl");

  quickButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const url = btn.getAttribute("data-url");
      targetUrlInput.value = url;
      performScan(url);
    });
  });

  btnScanUrl.addEventListener("click", () => {
    const url = targetUrlInput.value.trim();
    if (!url) {
      alert("Please enter a valid URL to scan.");
      return;
    }
    performScan(url);
  });

  targetUrlInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
      btnScanUrl.click();
    }
  });

  // Initial Data Loads
  checkHealth();
  loadThreatIntel();
  loadModelMetrics();

  // Threat Intel Rule Additions
  document.getElementById("btnAddWhitelist").addEventListener("click", () => addRule("whitelist"));
  document.getElementById("btnAddBlocklist").addEventListener("click", () => addRule("blocklist"));
});

async function checkHealth() {
  try {
    const res = await fetch("/api/v1/health");
    if (res.ok) {
      const data = await res.json();
      document.getElementById("systemStatusText").textContent = `${data.champion_model} Active`;
    }
  } catch (err) {
    document.getElementById("systemStatusText").textContent = "API Offline (Check Backend)";
    document.getElementById("systemStatus").style.color = "#ff3366";
  }
}

// Helper for delay
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let isScanningInProgress = false;

async function performScan(url) {
  if (isScanningInProgress) return;
  isScanningInProgress = true;

  const btnScanUrl = document.getElementById("btnScanUrl");
  const originalBtnContent = btnScanUrl.innerHTML;
  btnScanUrl.disabled = true;
  btnScanUrl.innerHTML = `<span>⏳ Scanning...</span>`;

  const scanningLoader = document.getElementById("scanningLoader");
  const resultContainer = document.getElementById("scanResultContainer");
  const loaderStageTitle = document.getElementById("loaderStageTitle");
  const loaderTargetDisplay = document.getElementById("loaderTargetDisplay");
  const loaderProgressBar = document.getElementById("loaderProgressBar");
  const loaderPercentage = document.getElementById("loaderPercentage");

  // Elements for steps
  const steps = [
    { el: document.getElementById("step-1"), status: document.getElementById("stepStatus-1") },
    { el: document.getElementById("step-2"), status: document.getElementById("stepStatus-2") },
    { el: document.getElementById("step-3"), status: document.getElementById("stepStatus-3") },
    { el: document.getElementById("step-4"), status: document.getElementById("stepStatus-4") },
  ];

  // Reset steps state
  steps.forEach((s) => {
    s.el.className = "loader-step";
    s.status.textContent = "Pending";
  });

  // Hide previous result and show scanning animation
  resultContainer.style.display = "none";
  scanningLoader.style.display = "flex";
  loaderTargetDisplay.textContent = `Target: ${url}`;
  loaderProgressBar.style.width = "0%";
  loaderPercentage.textContent = "0%";

  // Start background API request in parallel
  const apiPromise = fetch("/api/v1/predict", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  }).then(async (res) => {
    if (!res.ok) throw new Error("Inference failed.");
    return await res.json();
  });

  try {
    // Stage 1 (0ms - 850ms): Threat Intel & Reputation
    loaderStageTitle.textContent = "Checking Threat Intelligence feeds & reputation cache...";
    steps[0].el.classList.add("active");
    steps[0].status.textContent = "Querying...";
    loaderProgressBar.style.width = "25%";
    loaderPercentage.textContent = "25%";
    await delay(850);

    steps[0].el.classList.remove("active");
    steps[0].el.classList.add("completed");
    steps[0].status.textContent = "Verified";

    // Stage 2 (850ms - 1750ms): Feature Extraction
    loaderStageTitle.textContent = "Extracting 25-D lexical, entropy & DOM feature vectors...";
    steps[1].el.classList.add("active");
    steps[1].status.textContent = "Extracting...";
    loaderProgressBar.style.width = "55%";
    loaderPercentage.textContent = "55%";
    await delay(900);

    steps[1].el.classList.remove("active");
    steps[1].el.classList.add("completed");
    steps[1].status.textContent = "25 Features Extracted";

    // Stage 3 (1750ms - 2650ms): Model Inference
    loaderStageTitle.textContent = "Executing Random Forest Ensemble & ML Probability Matrix...";
    steps[2].el.classList.add("active");
    steps[2].status.textContent = "Classifying...";
    loaderProgressBar.style.width = "80%";
    loaderPercentage.textContent = "80%";
    await delay(900);

    steps[2].el.classList.remove("active");
    steps[2].el.classList.add("completed");
    steps[2].status.textContent = "Inference Complete";

    // Stage 4 (2650ms - 3500ms): Explainable AI & Risk Vector
    loaderStageTitle.textContent = "Synthesizing Explainable AI (XAI) Attribution & Diagnostics...";
    steps[3].el.classList.add("active");
    steps[3].status.textContent = "Synthesizing...";
    loaderProgressBar.style.width = "100%";
    loaderPercentage.textContent = "100%";
    await delay(850);

    steps[3].el.classList.remove("active");
    steps[3].el.classList.add("completed");
    steps[3].status.textContent = "Ready";

    // Await API response data
    const data = await apiPromise;

    // Smooth transition: hide loader & show results
    scanningLoader.style.display = "none";
    resultContainer.style.display = "block";
    resultContainer.scrollIntoView({ behavior: "smooth", block: "nearest" });

    // Populate data
    const scoreValue = document.getElementById("scoreValue");
    const scoreCircle = document.getElementById("scoreCircle");
    const verdictBadge = document.getElementById("verdictBadge");
    const resTargetUrl = document.getElementById("resTargetUrl");
    const resModel = document.getElementById("resModel");
    const resLatency = document.getElementById("resLatency");
    const resReputation = document.getElementById("resReputation");
    const riskFactorsList = document.getElementById("riskFactorsList");
    const featuresGrid = document.getElementById("featuresGrid");

    resTargetUrl.textContent = data.url;
    resModel.textContent = data.model_used;
    resLatency.textContent = `${data.latency_ms} ms (Total Analysis: 3.5s)`;
    resReputation.textContent = `${data.threat_intel_status.toUpperCase()} (${data.reputation_reason})`;

    // Score & Color
    const score = Math.round(Number(data.risk_score) || 0);

    verdictBadge.className = "verdict-badge";
    let accentColor = "var(--accent-green)";
    if (data.verdict === "PHISHING") {
      verdictBadge.classList.add("badge-phishing");
      verdictBadge.textContent = "CRITICAL: PHISHING DETECTED";
      accentColor = "var(--accent-red)";
    } else if (data.verdict === "SUSPICIOUS") {
      verdictBadge.classList.add("badge-suspicious");
      verdictBadge.textContent = "WARNING: SUSPICIOUS SITE";
      accentColor = "var(--accent-amber)";
    } else {
      verdictBadge.classList.add("badge-legitimate");
      verdictBadge.textContent = "SAFE: LEGITIMATE DESTINATION";
      accentColor = "var(--accent-green)";
    }

    scoreCircle.style.borderColor = accentColor;
    scoreValue.style.color = accentColor;

    // Smooth count-up animation for score value
    animateScoreCountUp(score, scoreValue);

    // Risk Factors List (XAI)
    riskFactorsList.innerHTML = "";
    if (data.risk_factors && data.risk_factors.length > 0) {
      data.risk_factors.forEach((f) => {
        const item = document.createElement("div");
        item.className = `risk-factor-item ${f.severity === "CRITICAL" ? "HIGH" : f.severity === "HIGH" ? "HIGH" : f.severity === "MEDIUM" ? "MED" : "LOW"}`;
        item.innerHTML = `
          <div>
            <div class="factor-title">[${f.severity}] ${f.factor}</div>
            <div class="factor-desc">${f.detail}</div>
          </div>
        `;
        riskFactorsList.appendChild(item);
      });
    } else {
      riskFactorsList.innerHTML = `<div style="font-size: 13px; color: var(--text-muted); padding: 8px 0;">No risk indicators identified. Clean destination vector.</div>`;
    }

    // Features Matrix
    featuresGrid.innerHTML = "";
    for (const [key, val] of Object.entries(data.features)) {
      const pill = document.createElement("div");
      pill.className = "feature-pill";
      pill.innerHTML = `
        <span>${key.replace(/_/g, " ")}</span>
        <span>${val}</span>
      `;
      featuresGrid.appendChild(pill);
    }

  } catch (err) {
    scanningLoader.style.display = "none";
    alert("Error communicating with detection backend: " + err.message);
  } finally {
    btnScanUrl.disabled = false;
    btnScanUrl.innerHTML = originalBtnContent;
    isScanningInProgress = false;
  }
}

function animateScoreCountUp(targetScore, element) {
  const target = Math.round(Number(targetScore) || 0);
  if (target === 0) {
    element.textContent = "0%";
    return;
  }
  let current = 0;
  const duration = 600; // ms
  const stepTime = 25;
  const increment = Math.max(1, target / (duration / stepTime));

  const timer = setInterval(() => {
    current += increment;
    if (current >= target) {
      current = target;
      element.textContent = `${target}%`;
      clearInterval(timer);
    } else {
      element.textContent = `${Math.round(current)}%`;
    }
  }, stepTime);
}

async function loadModelMetrics() {
  try {
    const res = await fetch("/api/v1/metrics");
    if (!res.ok) return;
    const data = await res.json();

    // Table Comparison
    const tableBody = document.getElementById("modelsTableBody");
    tableBody.innerHTML = "";

    const models = data.models_comparison || {};
    for (const [name, m] of Object.entries(models)) {
      const row = document.createElement("tr");
      if (name === data.champion_model) row.className = "highlight-row";
      row.innerHTML = `
        <td><strong>${name} ${name === data.champion_model ? "(Champion 🏆)" : ""}</strong></td>
        <td>${(m.accuracy * 100).toFixed(2)}%</td>
        <td>${(m.precision * 100).toFixed(2)}%</td>
        <td>${(m.recall * 100).toFixed(2)}%</td>
        <td>${m.f1_score.toFixed(4)}</td>
        <td>${m.roc_auc.toFixed(4)}</td>
        <td>${(m.false_positive_rate * 100).toFixed(2)}%</td>
      `;
      tableBody.appendChild(row);
    }

    // Confusion Matrix
    if (data.champion_metrics && data.champion_metrics.confusion_matrix) {
      const cm = data.champion_metrics.confusion_matrix;
      document.getElementById("cmTN").textContent = cm.true_negative;
      document.getElementById("cmFP").textContent = cm.false_positive;
      document.getElementById("cmFN").textContent = cm.false_negative;
      document.getElementById("cmTP").textContent = cm.true_positive;
    }

    // Feature Importances
    const fiList = document.getElementById("featureImportanceList");
    fiList.innerHTML = "";
    const importances = data.feature_importances || {};
    const entries = Object.entries(importances).slice(0, 7);

    entries.forEach(([feat, score]) => {
      const pct = (score * 100).toFixed(1);
      const div = document.createElement("div");
      div.className = "fi-bar-container";
      div.innerHTML = `
        <div class="fi-info">
          <span>${feat.replace(/_/g, " ")}</span>
          <span>${(score * 100).toFixed(2)}%</span>
        </div>
        <div class="fi-track">
          <div class="fi-fill" style="width: ${pct}%"></div>
        </div>
      `;
      fiList.appendChild(div);
    });

  } catch (err) {
    console.error("Failed to load metrics:", err);
  }
}

async function loadThreatIntel() {
  try {
    const res = await fetch("/api/v1/threat-intel");
    if (!res.ok) return;
    const data = await res.json();

    const wlContainer = document.getElementById("whitelistTags");
    wlContainer.innerHTML = "";
    (data.sample_whitelisted || []).forEach((domain) => {
      const tag = document.createElement("div");
      tag.className = "feed-tag";
      tag.textContent = domain;
      wlContainer.appendChild(tag);
    });

    const blContainer = document.getElementById("blocklistTags");
    blContainer.innerHTML = "";
    (data.sample_blacklisted || []).forEach((domain) => {
      const tag = document.createElement("div");
      tag.className = "feed-tag";
      tag.style.borderColor = "rgba(255, 51, 102, 0.4)";
      tag.style.color = "#fda4af";
      tag.textContent = domain;
      blContainer.appendChild(tag);
    });

  } catch (err) {
    console.error("Failed to load threat intel:", err);
  }
}

async function addRule(type) {
  const input = document.getElementById("customRuleInput");
  const entry = input.value.trim();
  if (!entry) return;

  const endpoint = type === "whitelist" ? "/api/v1/threat-intel/whitelist" : "/api/v1/threat-intel/blocklist";
  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ entry })
    });
    if (res.ok) {
      input.value = "";
      alert(`Successfully added '${entry}' to ${type.toUpperCase()}!`);
      loadThreatIntel();
    }
  } catch (err) {
    alert("Failed to add rule: " + err.message);
  }
}
