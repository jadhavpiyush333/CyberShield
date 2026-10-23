
"use strict";

const titles = {
  dashboard: "Security Overview",
  url: "URL Threat Scanner",
  sms: "SMS & Scam Scanner",
  network: "Network Intrusion Detection",
  malware: "Malware Behaviour",
  email: "Email Security",
  social: "Social Media Scam Scanner",
  qr: "QR Code Scanner",
  apk: "APK Static Analyzer",
  learning: "Learning Center"
};

const $ = (id) => document.getElementById(id);

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

async function api(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.error || data.message || `Request failed (${response.status})`
    );
  }

  return data;
}

function setPage(pageId) {
  if (!titles[pageId]) return;

  document.querySelectorAll(".nav").forEach((button) => {
    button.classList.toggle("active", button.dataset.page === pageId);
  });

  document.querySelectorAll(".page").forEach((page) => {
    page.classList.toggle("active", page.id === pageId);
  });

  if ($("title")) $("title").textContent = titles[pageId];
  if ($("crumb")) $("crumb").textContent = pageId.toUpperCase();

  $("sidebar")?.classList.remove("open");

  if (pageId === "learning") {
    refreshLearning();
  }
}

// Sidebar navigation
document.querySelectorAll(".nav").forEach((button) => {
  button.addEventListener("click", () => setPage(button.dataset.page));
});

// Dashboard shortcuts
document.querySelectorAll("[data-go]").forEach((button) => {
  button.addEventListener("click", () => setPage(button.dataset.go));
});

document.querySelectorAll("[data-home]").forEach((link) => {
  link.addEventListener("click", (event) => {
    event.preventDefault();
    setPage("dashboard");
  });
});

$("mobileMenu")?.addEventListener("click", () => {
  $("sidebar")?.classList.toggle("open");
});

// Scan using the existing Flask API
async function scan(kind) {
  const fields = {
    url: ["urlInput", "urlOut"],
    message: ["smsInput", "smsOut"],
    network: ["networkInput", "networkOut"],
    behavior: ["malwareInput", "malwareOut"]
  };

  const config = fields[kind];
  if (!config) {
    alert("Unknown scan type.");
    return;
  }

  const [inputId, outputId] = config;
  const input = $(inputId);
  const output = $(outputId);

  if (!input || !output) {
    alert("Could not find the scan input or output element.");
    return;
  }

  const raw = input.value.trim();

  if (!raw) {
    output.innerHTML =
      '<div class="result-error">Enter input before scanning.</div>';
    input.focus();
    return;
  }

  let body;

  if (kind === "url") {
    body = { url: raw };
  } else if (kind === "message") {
    // Flask's /api/scan/message route reads data["text"].
    body = { text: raw };
  } else {
    try {
      body = JSON.parse(raw);

      if (!body || Array.isArray(body) || typeof body !== "object") {
        throw new Error("Expected a JSON object.");
      }
    } catch {
      output.innerHTML =
        '<div class="result-error">Enter a valid JSON object, for example {"event_type":"brute_force","failed_logins":30}.</div>';
      return;
    }
  }

  const scanButton = document.querySelector(
    `[onclick="scan('${kind}')"]`
  );

  if (scanButton) {
    scanButton.disabled = true;
    scanButton.dataset.originalText = scanButton.textContent;
  }

  output.innerHTML =
    '<div class="result-loading"><span class="loader"></span>Analysing submitted data…</div>';

  try {
    const result = await api(`/api/scan/${kind}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });

    window.last = { kind, input: body, result };
    renderScanResult(output, result);
  } catch (error) {
    output.innerHTML = `
      <div class="result-error">
        <strong>Scan failed</strong>
        <p>${escapeHTML(error.message)}</p>
      </div>
    `;
  } finally {
    if (scanButton) {
      scanButton.disabled = false;
    }
  }
}

function renderScanResult(output, result) {
  const confidence = Number(result.confidence);
  const confidenceText = Number.isFinite(confidence)
    ? `${Math.round(confidence * 100)}%`
    : "Not provided";

  const evidence = Array.isArray(result.evidence)
    ? result.evidence.map((item) =>
        `<div>› ${escapeHTML(item)}</div>`
      ).join("")
    : '<div>No evidence details were provided by the detector.</div>';

  output.innerHTML = `
    <article class="threat">
      <div class="eyebrow">DETECTION RESULT</div>
      <h3>${escapeHTML(result.threat_type || "Unknown classification")}</h3>
      <span class="mini-badge">${escapeHTML(result.severity || "Severity not provided")}</span>
      <div class="risk">${escapeHTML(result.risk_score ?? "—")}<span style="font-size:13px;color:var(--muted)"> / 100 risk score</span></div>
      <p>Confidence: <strong>${confidenceText}</strong></p>
      <div class="info-divider"></div>
      <div class="eyebrow">EVIDENCE RETURNED BY THE DETECTOR</div>
      <div class="evidence">${evidence}</div>
      <button class="primary feedback-button" type="button" onclick="sendFeedback()">Submit for review <span>→</span></button>
    </article>
  `;
}

// Submit the latest scan result for human review
async function sendFeedback() {
  if (!window.last) {
    alert("Run a scan before submitting feedback.");
    return;
  }

  const buttons = document.querySelectorAll(".feedback-button");
  buttons.forEach((button) => { button.disabled = true; });

  try {
    const data = await api("/api/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(window.last)
    });

    const outputId = {
      url: "urlOut",
      message: "smsOut",
      network: "networkOut",
      behavior: "malwareOut",
      social: "socialOut",
      email: "emailOut",
      qr: "qrOut",
      apk: "apkOut"
    }[window.last.kind];

    if (outputId && $(outputId)) {
      const notice = document.createElement("p");
      notice.className = "input-hint";
      notice.textContent =
        `Feedback #${data.feedback_id} was submitted for human review.`;
      $(outputId).appendChild(notice);
    }

    await refreshLearning();
  } catch (error) {
    alert(`Could not submit feedback: ${error.message}`);
  } finally {
    buttons.forEach((button) => { button.disabled = false; });
  }
}


// Phase 2: scan copied social media content.
async function scanSocial() {
  const input = $("socialInput");
  const output = $("socialOut");
  if (!input || !output) return;

  const text = input.value.trim();
  if (!text) {
    output.innerHTML = '<div class="result-error">Paste a post or message before scanning.</div>';
    input.focus();
    return;
  }

  const button = document.querySelector('[onclick="scanSocial()"]');
  if (button) button.disabled = true;
  output.innerHTML = '<div class="result-loading"><span class="loader"></span>Analysing message…</div>';

  try {
    const body = { text };
    const result = await api("/api/scan/social", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    window.last = { kind: "social", input: body, result };
    renderScanResult(output, result);
  } catch (error) {
    output.innerHTML = `<div class="result-error"><strong>Scan failed</strong><p>${escapeHTML(error.message)}</p></div>`;
  } finally {
    if (button) button.disabled = false;
  }
}

// Phase 2: upload an email, QR image or APK using multipart form data.
async function scanUpload(kind) {
  const config = {
    email: { input: "emailFile", output: "emailOut", endpoint: "/api/scan/email", label: "email" },
    qr: { input: "qrFile", output: "qrOut", endpoint: "/api/scan/qr", label: "QR image" },
    apk: { input: "apkFile", output: "apkOut", endpoint: "/api/scan/apk", label: "APK" }
  }[kind];

  if (!config) return;

  const input = $(config.input);
  const output = $(config.output);
  const file = input?.files?.[0];

  if (!input || !output || !file) {
    if (output) output.innerHTML = `<div class="result-error">Choose a ${config.label} file before scanning.</div>`;
    return;
  }

  const button = document.querySelector(`[onclick="scanUpload('${kind}')"]`);
  if (button) button.disabled = true;
  output.innerHTML = '<div class="result-loading"><span class="loader"></span>Inspecting file locally…</div>';

  try {
    const form = new FormData();
    form.append("file", file);

    // Do not set Content-Type manually; the browser supplies the multipart boundary.
    const result = await api(config.endpoint, {
      method: "POST",
      body: form
    });

    window.last = {
      kind,
      input: { filename: file.name, size_bytes: file.size },
      result
    };
    renderScanResult(output, result);
  } catch (error) {
    output.innerHTML = `<div class="result-error"><strong>Scan failed</strong><p>${escapeHTML(error.message)}</p></div>`;
  } finally {
    if (button) button.disabled = false;
  }
}

// Render the current pending review queue
function renderPending(items) {
  const container = $("pendingList");
  if (!container) return;

  if (!Array.isArray(items)) {
    container.innerHTML = `
      <div class="empty-state">
        <strong>Unexpected response</strong>
        <p>The review queue response was not in the expected format.</p>
      </div>`;
    return;
  }

  if (items.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <strong>✓ Review queue is clear</strong>
        <p>No feedback items are waiting for review. New submitted feedback will appear here.</p>
      </div>`;
    return;
  }

  container.innerHTML = items.map((item) => {
    const id = Number(item.id);

    if (!Number.isSafeInteger(id) || id < 1) return "";

    let payload;
    try {
      payload = JSON.stringify(item.payload ?? {}, null, 2);
    } catch {
      payload = String(item.payload ?? "");
    }

    const confidence = Number(item.confidence);
    const confidenceText = Number.isFinite(confidence)
      ? `${Math.round(confidence * 100)}%`
      : "Not provided";

    return `
      <article class="review-item" data-feedback-id="${id}">
        <div class="review-heading">
          <div>
            <span class="review-id">FEEDBACK #${id}</span>
            <h3>${escapeHTML(item.kind || "Unknown")} report</h3>
          </div>
          <span class="pending-tag">Pending</span>
        </div>

        <div class="review-meta">
          <span>Prediction: <b>${escapeHTML(item.prediction || "Unknown")}</b></span>
          <span>Confidence: <b>${escapeHTML(confidenceText)}</b></span>
          <span>Submitted: ${escapeHTML(item.created_at || "Unknown")}</span>
        </div>

        <details>
          <summary>View submitted input</summary>
          <pre>${escapeHTML(payload)}</pre>
        </details>

        <div class="review-actions">
          <button class="review-verify" type="button" onclick="reviewFeedback(${id}, 'confirmed')">✓ Verify threat</button>
          <button class="review-fp" type="button" onclick="reviewFeedback(${id}, 'false_positive')">◇ False positive</button>
          <button class="review-reject" type="button" onclick="reviewFeedback(${id}, 'rejected')">× Reject</button>
        </div>
      </article>`;
  }).join("");
}

// Refresh learning statistics and queue
async function refreshLearning() {
  const message = $("learningMessage");
  const refreshButton = $("refreshLearningButton");

  if (message) message.textContent = "Loading learning data…";
  if (refreshButton) refreshButton.disabled = true;

  try {
    const [stats, queue] = await Promise.all([
      api("/api/learning/stats"),
      api("/api/learning/pending")
    ]);

    if (!queue || !Array.isArray(queue.items)) {
      throw new Error("The pending queue response is invalid.");
    }

    const values = {
      pending: stats.pending ?? 0,
      confirmed: stats.confirmed ?? 0,
      false_positive: stats.false_positive ?? 0,
      rejected: stats.rejected ?? 0
    };

    if ($("pending")) $("pending").textContent = values.pending;
    if ($("lPending")) $("lPending").textContent = values.pending;
    if ($("lConfirmed")) $("lConfirmed").textContent = values.confirmed;
    if ($("lFP")) $("lFP").textContent = values.false_positive;
    if ($("lRejected")) $("lRejected").textContent = values.rejected;
    if ($("navPending")) $("navPending").textContent = values.pending;

    renderPending(queue.items);

    if (message) message.textContent = "";
  } catch (error) {
    if (message) {
      message.textContent = `Could not load learning data: ${error.message}`;
    }

    // Do not pretend an API failure means an empty queue.
    const container = $("pendingList");
    if (container) {
      container.innerHTML = `
        <div class="empty-state">
          <strong>Unable to load review queue</strong>
          <p>Check the server connection and try refreshing.</p>
        </div>`;
    }
  } finally {
    if (refreshButton) refreshButton.disabled = false;
  }
}

// Apply a human review verdict
async function reviewFeedback(id, verdict) {
  const labels = {
    confirmed: "verify this threat",
    false_positive: "mark this as a false positive",
    rejected: "reject this feedback"
  };

  if (!Number.isSafeInteger(Number(id)) || Number(id) < 1 || !labels[verdict]) {
    alert("Invalid review action.");
    return;
  }

  if (!confirm(`Are you sure you want to ${labels[verdict]}?`)) return;

  const message = $("learningMessage");
  const card = document.querySelector(`[data-feedback-id="${Number(id)}"]`);
  const buttons = card ? card.querySelectorAll("button") : [];

  buttons.forEach((button) => { button.disabled = true; });
  if (message) message.textContent = `Saving review for feedback #${id}…`;

  try {
    await api(`/api/feedback/${Number(id)}/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verdict })
    });

    if (message) {
      message.textContent = `Feedback #${id} reviewed successfully.`;
    }

    await refreshLearning();
  } catch (error) {
    if (message) message.textContent = `Review failed: ${error.message}`;
    buttons.forEach((button) => { button.disabled = false; });
  }
}

// Export reviewed samples. Flask defines this endpoint as POST.
async function exportVerified() {
  const button = $("exportButton");
  if (button) button.disabled = true;

  try {
    const result = await api("/api/learning/export", {
      method: "POST"
    });

    if (result.path) {
      alert(`Verified samples exported to: ${result.path}`);
    } else {
      alert("Export request completed.");
    }
  } catch (error) {
    alert(`Export failed: ${error.message}`);
  } finally {
    if (button) button.disabled = false;
  }
}

// Initial learning counts
refreshLearning();
