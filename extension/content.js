/**
 * AI Phishing Sentinel - Content Script
 * Performs lightweight DOM analysis for client-side credential Harvesting detection.
 */

(function () {
  // Extract password fields & insecure form action warnings
  const forms = document.querySelectorAll("form");
  const passwordInputs = document.querySelectorAll("input[type='password']");
  
  if (passwordInputs.length > 0 && window.location.protocol === "http:") {
    console.warn("[AI Phishing Sentinel] Insecure password submission field detected over HTTP!");
  }
})();
