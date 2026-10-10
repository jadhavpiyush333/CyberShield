
const titles = {
  dashboard: "Security Overview",
  url: "URL Threat Scanner",
  sms: "SMS / Scam Scanner",
  network: "Network Intrusion Detection",
  malware: "Malware Behaviour",
  learning: "Controlled Learning"
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

// Navigation
document.querySelectorAll(".nav").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".nav").forEach((item) => {
      item.classList.toggle("active", item === button);
    });

    document.querySelectorAll(".page").forEach((page) => {
      page.classList.toggle(
        "active",
        page.id === button.dataset.page
      );
    });

    if ($("title")) {
      $("title").textContent =
        titles[button.dataset.page] || "CyberShield";
    }

    if (button.dataset.page === "learning") {
      refreshLearning();
    }
  });
});

// Security scan
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
    output.textContent = "Enter input before scanning.";
    return;
  }

  let body;

  if (kind === "url") {
    body = { url: raw };
  } else if (kind === "message") {
    body = { message: raw };
  } else {
    try {
      body = JSON.parse(raw);
    } catch {
      output.textContent =
        "Invalid JSON. Enter a valid JSON object.";
      return;
    }
  }

  output.textContent = "Analysing...";

  try {
    const result = await api(`/api/scan/${kind}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    });

    window.last = {
      kind,
      input: body,
      result
    };

    output.innerHTML = `
      <div class="threat">
        <div class="eyebrow">DETECTION RESULT</div>

        <h3>
          ${escapeHTML(result.threat_type || "UNKNOWN")}
          ·
          ${escapeHTML(result.severity || "UNKNOWN")}
        </h3>

        <div class="risk">
          ${escapeHTML(result.risk_score ?? 0)}/100
        </div>

        <p>
          Confidence:
          ${Math.round(Number(result.confidence || 0) * 100)}%
        </p>

        <div class="evidence">
          ${
            Array.isArray(result.evidence)
              ? result.evidence
                  .map((item) => "✓ " + escapeHTML(item))
                  .join("<br>")
              : ""
          }
        </div>

        <button
          class="primary"
          type="button"
          onclick="sendFeedback()"
        >
          Submit for Review
        </button>
      </div>
    `;
  } catch (error) {
    output.textContent = `Scan failed: ${error.message}`;
  }
}

// Submit the latest scan to the review queue
async function sendFeedback() {
  if (!window.last) {
    alert("Run a scan before submitting feedback.");
    return;
  }

  try {
    const data = await api("/api/feedback", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(window.last)
    });

    alert(
      `Feedback #${data.feedback_id} was submitted for review.`
    );

    await refreshLearning();
  } catch (error) {
    alert(`Could not submit feedback: ${error.message}`);
  }
}

// Display pending feedback items
function renderPending(items) {
  const container = $("pendingList");

  if (!container) return;

  if (!Array.isArray(items) || items.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <strong>Review queue is clear</strong>
        <p>No feedback items are waiting for review.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = items.map((item) => {
    const id = Number(item.id);
    const payload = JSON.stringify(item.payload ?? {}, null, 2);
    const confidence = Math.round(
      Number(item.confidence || 0) * 100
    );

    return `
      <article class="review-item">
        <div class="review-heading">
          <div>
            <span class="review-id">
              FEEDBACK #${escapeHTML(id)}
            </span>
            <h3>${escapeHTML(item.kind)} report</h3>
          </div>

          <span class="pending-tag">Pending</span>
        </div>

        <div class="review-meta">
          <span>
            Prediction:
            <b>${escapeHTML(item.prediction || "Unknown")}</b>
          </span>

          <span>
            Confidence:
            <b>${confidence}%</b>
          </span>

          <span>
            Submitted:
            ${escapeHTML(item.created_at || "Unknown")}
          </span>
        </div>

        <details>
          <summary>View submitted input</summary>
          <pre>${escapeHTML(payload)}</pre>
        </details>

        <div class="review-actions">
          <button
            class="review-verify"
            type="button"
            onclick="reviewFeedback(${id}, 'confirmed')"
          >
            Verify Threat
          </button>

          <button
            class="review-fp"
            type="button"
            onclick="reviewFeedback(${id}, 'false_positive')"
          >
            Mark False Positive
          </button>

          <button
            class="review-reject"
            type="button"
            onclick="reviewFeedback(${id}, 'rejected')"
          >
            Reject
          </button>
        </div>
      </article>
    `;
  }).join("");
}

// Refresh counts and pending queue
async function refreshLearning() {
  const message = $("learningMessage");

  if (message) {
    message.textContent = "Loading learning data...";
  }

  try {
    const [stats, queue] = await Promise.all([
      api("/api/learning/stats"),
      api("/api/learning/pending")
    ]);

    if ($("pending")) {
      $("pending").textContent = stats.pending ?? 0;
    }

    if ($("lPending")) {
      $("lPending").textContent = stats.pending ?? 0;
    }

    if ($("lConfirmed")) {
      $("lConfirmed").textContent = stats.confirmed ?? 0;
    }

    if ($("lFP")) {
      $("lFP").textContent = stats.false_positive ?? 0;
    }

    if ($("lRejected")) {
      $("lRejected").textContent = stats.rejected ?? 0;
    }

    // The API in Step 4 returns {"items": [...]}.
    renderPending(queue.items || []);

    if (message) {
      message.textContent = "";
    }
  } catch (error) {
    if (message) {
      message.textContent =
        `Could not load learning data: ${error.message}`;
    }

    renderPending([]);
  }
}

// Review one feedback item
async function reviewFeedback(id, verdict) {
  const labels = {
    confirmed: "verify this threat",
    false_positive: "mark this as a false positive",
    rejected: "reject this feedback"
  };

  if (!labels[verdict]) {
    alert("Invalid review action.");
    return;
  }

  if (!confirm(`Are you sure you want to ${labels[verdict]}?`)) {
    return;
  }

  const message = $("learningMessage");

  try {
    await api(`/api/feedback/${id}/review`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ verdict })
    });

    if (message) {
      message.textContent = `Feedback #${id} reviewed successfully.`;
    }

    await refreshLearning();
  } catch (error) {
    if (message) {
      message.textContent = `Review failed: ${error.message}`;
    }
  }
}

// Export reviewed samples using the existing GET route
async function exportVerified() {
  try {
    const result = await api("/api/learning/export");

    if (result.path) {
      alert(`Verified samples exported to: ${result.path}`);
    } else {
      alert("Export request completed.");
    }
  } catch (error) {
    alert(`Export failed: ${error.message}`);
  }
}

// Initial statistics
refreshLearning();
