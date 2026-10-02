(() => {
  "use strict";

  const state = {
    type: "username",
    sources: [],
    report: null,
    registry: [],
    history: []
  };

  const TARGETS = [
    ["username", "IDENTIFIER", "Public handle"],
    ["domain", "NETWORK", "Domain / infra"],
    ["email", "IDENTIFIER", "Email exposure"],
    ["phone", "IDENTIFIER", "Phone exposure"],
    ["url", "WEB", "Historical URL"],
    ["ip", "NETWORK", "IP intelligence"],
    ["asn", "NETWORK", "ASN registration"],
    ["hash", "FILE", "Hash intelligence"],
    ["file", "FILE", "Local metadata"],
    ["person", "PERSON", "Public name query"],
    ["password", "PRIVACY", "Exposure check"]
  ];

  const CAPABILITY_TEXT = {
    username: "public account / profile research",
    domain: "registration / DNS / archive / infrastructure research",
    email: "public account-presence / breach-exposure research",
    phone: "public phone exposure research",
    url: "historical and public URL intelligence",
    person: "public name/person query",
    ip: "public IP registration / host intelligence",
    asn: "public ASN registration research",
    hash: "file hash intelligence",
    file: "local file metadata and hashes",
    password: "privacy-preserving exposure prevalence"
  };

  const $ = function(selector) { return document.querySelector(selector); };
  const $$ = function(selector) { return Array.from(document.querySelectorAll(selector)); };

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function fmtDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  }

  function go(view) {
    $$(".nav-item").forEach(function(button) {
      button.classList.toggle("active", button.dataset.view === view);
    });
    $$(".view").forEach(function(section) {
      section.classList.toggle("active", section.id === "view-" + view);
    });
    const titles = {
      dashboard: "Investigation dashboard",
      investigation: "New investigation",
      history: "Investigation history",
      sources: "Sources & capabilities",
      results: "Investigation results"
    };
    $("#page-title").textContent = titles[view] || "xLFr4n OSINT";
  }

  async function api(path, options) {
    const request = options || {};
    const headers = Object.assign(
      { "Content-Type": "application/json" },
      request.headers || {}
    );
    const response = await fetch(path, Object.assign({}, request, { headers: headers }));
    const body = await response.json().catch(function() { return {}; });
    if (!response.ok) {
      throw new Error(body.error || ("HTTP " + response.status));
    }
    return body;
  }

  function renderTypes() {
    $("#type-grid").innerHTML = TARGETS.map(function(target) {
      const key = target[0];
      const badge = target[1];
      const label = target[2];
      return "<button class=\"type-btn " + (state.type === key ? "active" : "") + "\" data-target-type=\"" +
        escapeHtml(key) + "\"><b>" + escapeHtml(badge) + "</b>" + escapeHtml(label) + "</button>";
    }).join("");

    $$("[data-target-type]").forEach(function(button) {
      button.addEventListener("click", function() {
        state.type = button.dataset.targetType;
        state.sources = [];
        $("#target-value").value = "";
        updateTargetMode();
        renderTypes();
        loadSourcesForInvestigation().catch(showError);
      });
    });
  }

  function updateTargetMode() {
    const placeholders = {
      username: "xLFr4n",
      domain: "example.com",
      email: "user@example.com",
      phone: "+34 600 000 000",
      url: "https://example.com/",
      ip: "192.0.2.10",
      asn: "AS64500",
      hash: "sha256…",
      file: "/path/to/file.jpg",
      person: "Ada Lovelace",
      password: "Enter a password"
    };
    $("#target-value").placeholder = placeholders[state.type] || "Target";
    $("#target-value").type = state.type === "password" ? "password" : "text";
    $("#target-value").autocomplete = state.type === "password" ? "new-password" : "off";
    $("#input-suffix").textContent = state.type === "password" ? "privacy" : state.type;
    $("#password-note").classList.toggle("hidden", state.type !== "password");
  }

  async function loadHealth() {
    try {
      await api("/api/health");
      $("#server-status").textContent = "Engine online";
      $(".status-dot").classList.remove("off");
    } catch (error) {
      $("#server-status").textContent = "Engine unavailable";
      $(".status-dot").classList.add("off");
      console.error(error);
    }
  }

  async function loadSourcesForInvestigation() {
    const data = await api("/api/sources?type=" + encodeURIComponent(state.type));
    state.registry = data.sources || [];
    renderSourceList();
  }

  function providerStatus(item) {
    const status = item.status || "ready";
    const labels = {
      ready: "ready",
      "missing-dependency": "missing dependency",
      "missing-credentials": "missing credentials"
    };
    return {
      status: status,
      label: labels[status] || status
    };
  }

  function renderSourceList() {
    $("#source-list").innerHTML = state.registry.map(function(item) {
      const status = providerStatus(item);
      const unavailable = status.status !== "ready";
      const title = item.requirement ? " · " + item.requirement : "";
      return "<label class=\"source-check " + (unavailable ? "source-unavailable" : "") + "\" title=\"" +
        escapeHtml(title) + "\">" +
        "<input type=\"checkbox\" value=\"" + escapeHtml(item.name) + "\"" +
        (state.sources.includes(item.name) ? " checked" : "") +
        (unavailable ? " disabled" : "") + ">" +
        "<span>" + escapeHtml(item.name) + "</span>" +
        "<small class=\"source-status " + escapeHtml(status.status) + "\">" +
        escapeHtml(item.default_enabled ? "default · " : "opt-in · ") +
        escapeHtml(status.label) + "</small>" +
        "</label>";
    }).join("");

    $$("#source-list input").forEach(function(input) {
      input.addEventListener("change", function() {
        state.sources = $$("#source-list input:checked").map(function(item) { return item.value; });
      });
    });
  }

  function selectDefaults() {
    state.sources = state.registry
      .filter(function(item) { return item.default_enabled; })
      .map(function(item) { return item.name; });
    renderSourceList();
  }

  async function refreshHistory() {
    const data = await api("/api/reports");
    state.history = data.reports || [];
    renderDashboard();
    renderHistory();
  }

  function renderDashboard() {
    const reports = state.history;
    const totals = reports.reduce(function(acc, item) {
      acc.findings += Number(item.finding_count || 0);
      acc.entities += Number(item.entity_count || 0);
      acc.sources += Number(item.source_count || 0);
      return acc;
    }, { findings: 0, entities: 0, sources: 0 });

    $("#stat-reports").textContent = reports.length;
    $("#stat-findings").textContent = totals.findings;
    $("#stat-entities").textContent = totals.entities;
    $("#stat-sources").textContent = totals.sources;

    if (!reports.length) {
      $("#recent-list").innerHTML =
        "<div class=\"list-empty\">No investigations yet. Start with a public username, domain, email, IP, URL or hash.</div>";
      return;
    }

    $("#recent-list").innerHTML = reports.slice(0, 6).map(function(item) {
      return "<button class=\"history-row recent-row\" data-open-report=\"" + escapeHtml(item.scan_id) + "\">" +
        "<span class=\"history-query\">" + escapeHtml(item.query) + "</span>" +
        "<span class=\"history-muted\">" + Number(item.finding_count || 0) + " findings</span>" +
        "<span class=\"history-muted\">" + escapeHtml(fmtDate(item.started_at)) + "</span>" +
        "</button>";
    }).join("");

    bindOpenButtons();
  }

  function renderHistory() {
    if (!state.history.length) {
      $("#history-list").innerHTML = "<div class=\"list-empty\">No saved reports.</div>";
      return;
    }

    const header =
      "<div class=\"history-row header\">" +
      "<span>Target</span><span>Started</span><span>Findings</span><span>Sources</span><span>Entities</span><span>Errors</span><span></span></div>";

    const rows = state.history.map(function(item) {
      return "<div class=\"history-row\">" +
        "<span class=\"history-query\">" + escapeHtml(item.query) + "</span>" +
        "<span class=\"history-muted\">" + escapeHtml(fmtDate(item.started_at)) + "</span>" +
        "<span>" + Number(item.finding_count || 0) + "</span>" +
        "<span>" + Number(item.source_count || 0) + "</span>" +
        "<span>" + Number(item.entity_count || 0) + "</span>" +
        "<span>" + Number(item.error_count || 0) + "</span>" +
        "<button class=\"ghost-btn\" data-open-report=\"" + escapeHtml(item.scan_id) + "\">Open</button>" +
        "</div>";
    }).join("");

    $("#history-list").innerHTML = header + rows;
    bindOpenButtons();
  }

  function bindOpenButtons() {
    $$("[data-open-report]").forEach(function(button) {
      button.addEventListener("click", function() {
        openReport(button.dataset.openReport);
      });
    });
  }

  async function openReport(scanId) {
    try {
      const report = await api("/api/reports/" + encodeURIComponent(scanId));
      state.report = report;
      renderResults(report);
      go("results");
    } catch (error) {
      alert(error.message);
    }
  }

  function renderMetrics(report) {
    const summary = report.summary || {};
    const metrics = [
      ["Findings", Number(summary.finding_count || (report.findings || []).length)],
      ["Sources", Number(summary.source_count || 0)],
      ["Entities", Number(summary.entity_count || 0)],
      ["Relationships", Number(summary.relationship_count || 0)]
    ];
    const coverage = Number(summary.provider_count || (report.provider_runs || []).length);
    metrics.push(["Providers", coverage]);
    return "<div class=\"metric-grid\">" + metrics.map(function(metric) {
      return "<div class=\"metric\"><span>" + metric[0] + "</span><strong>" + metric[1] + "</strong></div>";
    }).join("") + "</div>";
  }

  function renderFindings(report) {
    const findings = report.findings || [];
    if (!findings.length) {
      return "<div class=\"list-empty\">No public findings returned by the selected providers.</div>";
    }

    return findings.map(function(item) {
      return "<div class=\"finding-row\">" +
        "<div class=\"finding-title\"><span class=\"finding-source\">" + escapeHtml(item.source) + "</span>" +
        "<strong>" + escapeHtml(item.title) + "</strong></div>" +
        "<div class=\"finding-url\">" + escapeHtml(item.url || "") + "</div>" +
        "<div class=\"finding-foot\">" +
        "<span class=\"confidence\">" + escapeHtml(item.category) + "</span>" +
        "<span class=\"confidence\">" + escapeHtml(item.confidence) + "</span>" +
        "<span class=\"confidence\">" + escapeHtml(fmtDate(item.observed_at)) + "</span>" +\n        (item.data && item.data.verification ? "<span class=\"confidence\">" + escapeHtml(item.data.verification) + "</span>" : "") +
        "</div></div>";
    }).join("");
  }

  function renderEntities(correlation) {
    const entities = (correlation && correlation.entities) || [];
    if (!entities.length) {
      return "<div class=\"list-empty\">No correlated entities.</div>";
    }

    return entities.slice(0, 40).map(function(entity) {
      return "<div class=\"entity-row\"><div><strong>" + escapeHtml(entity.value) + "</strong>" +
        "<div class=\"history-muted\">" + escapeHtml(entity.kind) + "</div></div>" +
        "<span>" + (entity.sources || []).length + " source(s)</span></div>";
    }).join("");
  }

  function renderGraph(correlation) {
    const entities = ((correlation && correlation.entities) || []).slice(0, 20);
    const relationships = (correlation && correlation.relationships) || [];
    if (!entities.length) {
      return "<div class=\"list-empty\">Nothing to draw yet.</div>";
    }

    const width = 500;
    const height = 330;
    const centerX = 250;
    const centerY = 156;
    const radius = Math.min(128, 40 + entities.length * 5);
    const positions = new Map();

    entities.forEach(function(entity, index) {
      const angle = (Math.PI * 2 * index) / entities.length - Math.PI / 2;
      positions.set(entity.key, {
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius
      });
    });

    const lines = relationships.map(function(rel) {
      const left = positions.get(rel.left_entity);
      const right = positions.get(rel.right_entity);
      if (!left || !right) return "";
      return "<line class=\"graph-line\" x1=\"" + left.x + "\" y1=\"" + left.y +
        "\" x2=\"" + right.x + "\" y2=\"" + right.y + "\" />";
    }).join("");

    const nodes = entities.map(function(entity) {
      const point = positions.get(entity.key);
      const label = String(entity.value || "").slice(0, 18);
      return "<g><circle class=\"graph-node\" cx=\"" + point.x + "\" cy=\"" + point.y +
        "\" r=\"19\"></circle><text class=\"graph-label\" x=\"" + point.x +
        "\" y=\"" + (point.y + 36) + "\">" + escapeHtml(label) + "</text></g>";
    }).join("");

    return "<svg class=\"graph\" viewBox=\"0 0 " + width + " " + height +
      "\" role=\"img\" aria-label=\"Correlation graph\">" + lines + nodes + "</svg>";
  }

  function renderProviderRuns(report) {
    const runs = report.provider_runs || [];
    if (!runs.length) {
      return "<div class=\"list-empty\">No provider execution records.</div>";
    }

    const labels = {
      findings: "findings",
      "no-findings": "no findings",
      error: "error",
      timeout: "timeout",
      skipped: "skipped"
    };

    return runs.map(function(run) {
      const status = run.status || "unknown";
      const label = labels[status] || status;
      const statusClass = status === "findings"
        ? "good"
        : (status === "error" || status === "timeout" ? "warn" : "");
      const detail = status === "findings"
        ? Number(run.finding_count || 0) + " finding(s)"
        : label;
      return "<div class=\"provider-run\">" +
        "<div><strong>" + escapeHtml(run.provider || "unknown") + "</strong>" +
        "<div class=\"history-muted\">" + escapeHtml(detail) + "</div></div>" +
        "<div class=\"provider-run-meta\"><span class=\"badge " + statusClass + "\">" +
        escapeHtml(label) + "</span><span>" + Number(run.duration_seconds || 0).toFixed(2) + "s</span></div>" +
        (run.skip_reason ? "<div class=\"provider-run-error\">" + escapeHtml(run.skip_reason) + "</div>" : "") +
        (run.error ? "<div class=\"provider-run-error\">" + escapeHtml(run.error) + "</div>" : "") +
        "</div>";
    }).join("");
  }

  function renderErrors(errors) {
    if (!errors || !errors.length) {
      return "<div class=\"list-empty\">No provider errors.</div>";
    }
    return errors.map(function(error) {
      return "<div class=\"error-row\"><b>" + escapeHtml(error.source || "unknown") +
        "</b><div>" + escapeHtml(error.error || "unknown error") + "</div></div>";
    }).join("");
  }

  function renderResults(report) {
    const summary = report.summary || {};
    const errors = report.errors || [];
    const skipped = Number(summary.provider_skipped || 0);
    const status = errors.length
      ? "<span class=\"badge warn\">" + errors.length + " provider error(s)</span>"
      : (skipped
        ? "<span class=\"badge warn\">" + skipped + " provider(s) skipped</span>"
        : "<span class=\"badge good\">clean execution</span>");

    $("#results-root").innerHTML =
      "<div class=\"result-header\"><div>" +
      "<div class=\"eyebrow\">" + escapeHtml(report.scan_id) + "</div>" +
      "<div class=\"query\">" + escapeHtml(report.query) + "</div>" +
      "<div class=\"result-meta\"><span class=\"badge\">" + escapeHtml(fmtDate(report.started_at)) +
      "</span>" + status + "<span class=\"badge\">JSON schema " +
      escapeHtml(report.schema_version || "—") + "</span></div></div>" +
      "<div class=\"badge\">" + Number(summary.category_count || 0) + " categories</div></div>" +
      renderMetrics(report) +
      "<div class=\"results-grid\">" +
      "<section class=\"panel results-card\"><div class=\"panel-head\"><div><div class=\"eyebrow\">COLLECTION</div><h3>Findings</h3></div></div>" +
      "<div class=\"card-body\">" + renderFindings(report) + "</div></section>" +
      "<section class=\"panel results-card graph-wrap\"><div class=\"panel-head\"><div><div class=\"eyebrow\">EXACT MATCHES</div><h3>Shared-selector graph</h3></div></div>" +
      "<div class=\"card-body\">" + renderGraph(report.correlation) + "</div></section>" +
      "<section class=\"panel results-card\"><div class=\"panel-head\"><div><div class=\"eyebrow\">ENTITIES</div><h3>Exact-selector entities</h3></div></div>" +
      "<div class=\"card-body\">" + renderEntities(report.correlation) + "</div></section>" +
      "<section class=\"panel results-card\" style=\"grid-column:1/-1\"><div class=\"panel-head\"><div><div class=\"eyebrow\">COLLECTION LEDGER</div><h3>Provider execution</h3></div></div>" +
      "<div class=\"card-body\">" + renderProviderRuns(report) + "</div></section>" +
      "<section class=\"panel results-card\"><div class=\"panel-head\"><div><div class=\"eyebrow\">ERROR LEDGER</div><h3>Provider errors</h3></div></div>" +
      "<div class=\"card-body\">" + renderErrors(errors) + "</div></section>" +
      "<section class=\"panel results-card\" style=\"grid-column:1/-1\"><div class=\"panel-head\"><div><div class=\"eyebrow\">EVIDENCE</div><h3>Raw normalized report</h3></div></div>" +
      "<div class=\"card-body\"><pre class=\"raw\">" + escapeHtml(JSON.stringify(report, null, 2)) + "</pre></div></section>" +
      "</div>";
  }

  async function renderRegistry() {
    const filter = $("#source-capability-filter").value;
    const path = "/api/sources" + (filter ? "?type=" + encodeURIComponent(filter) : "");
    const data = await api(path);
    const items = data.sources || [];
    $("#registry-grid").innerHTML = items.map(function(item) {
      const capabilities = item.capabilities || [];
      const status = providerStatus(item);
      return "<div class=\"registry-card\"><div class=\"registry-card-top\">" +
        "<strong>" + escapeHtml(item.name) + "</strong>" +
        "<span class=\"source-status " + escapeHtml(status.status) + "\">" +
        escapeHtml(item.default_enabled ? "default · " : "opt-in · ") +
        escapeHtml(status.label) + "</span></div>" +
        "<p>" + escapeHtml(capabilities.map(function(cap) {
          return CAPABILITY_TEXT[cap] || cap;
        }).join(" · ")) + "</p>" +
        "<div class=\"cap-badges\">" + capabilities.map(function(cap) {
          return "<span>" + escapeHtml(cap) + "</span>";
        }).join("") + "</div>" +
        (item.requirement ? "<div class=\"registry-requirement\">" + escapeHtml(item.requirement) + "</div>" : "") +
        "</div>";
    }).join("");
  }

  function showError(error) {
    $("#scan-error").textContent = error.message || String(error);
    $("#scan-error").classList.remove("hidden");
  }

  function sleep(ms) {
    return new Promise(function(resolve) { setTimeout(resolve, ms); });
  }

  async function waitForJob(jobId) {
    while (true) {
      const job = await api("/api/jobs/" + encodeURIComponent(jobId));
      if (job.status === "completed" && job.report) {
        return job.report;
      }
      if (job.status === "failed") {
        throw new Error(job.error || "Investigation job failed.");
      }
      if (job.stage === "queued") {
        $("#scan-btn-text").textContent = "Queued…";
      } else {
        $("#scan-btn-text").textContent = "Collecting intelligence…";
      }
      await sleep(700);
    }
  }

  async function runScan() {
    const value = $("#target-value").value.trim();
    const mode = $("#source-mode").value;

    if (!value) {
      showError(new Error("Enter a target first."));
      return;
    }

    $("#scan-error").classList.add("hidden");
    $("#run-scan-btn").disabled = true;
    $("#run-scan-btn").classList.add("loading");
    $("#scan-btn-text").textContent = "Submitting…";
    $("#scan-btn-icon").textContent = "◌";

    const payload = {
      type: state.type,
      value: value,
      timeout: Number($("#timeout").value || 10),
      sources: mode === "custom" ? state.sources : [],
      all_sources: mode === "all"
    };

    try {
      const job = await api("/api/jobs", {
        method: "POST",
        body: JSON.stringify(payload)
      });
      const report = await waitForJob(job.job_id);
      state.report = report;
      await refreshHistory();
      renderResults(report);
      go("results");
    } catch (error) {
      showError(error);
    } finally {
      $("#run-scan-btn").disabled = false;
      $("#run-scan-btn").classList.remove("loading");
      $("#scan-btn-text").textContent = "Run investigation";
      $("#scan-btn-icon").textContent = "⌁";
    }
  }

  function downloadReport() {
    if (!state.report) return;
    const blob = new Blob([JSON.stringify(state.report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = (state.report.scan_id || "report") + ".json";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  async function downloadMarkdown() {
    if (!state.report || !state.report.scan_id) return;
    try {
      const response = await fetch("/api/reports/" + encodeURIComponent(state.report.scan_id) + "/markdown");
      if (!response.ok) {
        const body = await response.json().catch(function() { return {}; });
        throw new Error(body.error || ("HTTP " + response.status));
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = (state.report.scan_id || "report") + ".md";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error(error);
      alert(error.message || "Markdown export failed.");
    }
  }

  async function copyScanId() {
    if (!state.report || !state.report.scan_id) return;
    try {
      await navigator.clipboard.writeText(state.report.scan_id);
    } catch (error) {
      console.error(error);
      alert(state.report.scan_id);
    }
  }

  $$(".nav-item").forEach(function(button) {
    button.addEventListener("click", function() {
      go(button.dataset.view);
      if (button.dataset.view === "history") refreshHistory().catch(console.error);
      if (button.dataset.view === "sources") renderRegistry().catch(console.error);
    });
  });

  $$("[data-view-jump]").forEach(function(button) {
    button.addEventListener("click", function() { go(button.dataset.viewJump); });
  });

  $("#quick-scan-btn").addEventListener("click", function() { go("investigation"); });
  $("#back-to-investigation").addEventListener("click", function() { go("investigation"); });
  $("#run-scan-btn").addEventListener("click", runScan);
  $("#target-value").addEventListener("keydown", function(event) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      runScan();
    }
  });
  $("#select-defaults").addEventListener("click", selectDefaults);
  $("#download-json").addEventListener("click", downloadReport);
  $("#download-markdown").addEventListener("click", downloadMarkdown);
  $("#copy-scan-id").addEventListener("click", copyScanId);
  $("#refresh-history").addEventListener("click", function() { refreshHistory().catch(console.error); });
  $("#source-capability-filter").addEventListener("change", function() { renderRegistry().catch(console.error); });

  $("#source-mode").addEventListener("change", function(event) {
    const mode = event.target.value;
    $("#custom-sources").classList.toggle("hidden", mode !== "custom");
    if (mode === "custom" && !state.sources.length) {
      selectDefaults();
    }
  });

  renderTypes();
  updateTargetMode();
  Promise.all([loadHealth(), loadSourcesForInvestigation(), refreshHistory()]).catch(console.error);
})();
