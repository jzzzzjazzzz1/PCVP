let currentScanId = null;
let currentExposure = null;
let currentServices = [];
let statusIntervalId = null;

document.addEventListener("DOMContentLoaded", async () => {
  const form = document.getElementById("scan-form");
  const statusDiv = document.getElementById("scan-status");
  const startBtn = document.getElementById("start-scan-btn");

  // Check server boot id to detect backend restarts and avoid restoring stale cached scans
  try {
    const hb = await fetch("/health");
    if (hb.ok) {
      const info = await hb.json();
      const serverBoot = info.boot_id || null;
      const savedBoot = localStorage.getItem("pcvp:bootId");
      if (!savedBoot || savedBoot !== serverBoot) {
        localStorage.removeItem("pcvp:lastScanId");
        localStorage.removeItem("pcvp:lastServicesHtml");
        localStorage.removeItem("pcvp:lastStats");
        localStorage.removeItem("pcvp:lastTarget");
        localStorage.removeItem("pcvp:lastExposure");
      }
      if (serverBoot) localStorage.setItem("pcvp:bootId", serverBoot);
    }
  } catch (e) {}

  const saved = localStorage.getItem("pcvp:lastScanId");
  if (saved) {
    try {
      const resp = await fetch(`/scan/${saved}`);
      if (resp.ok) {
        currentScanId = saved;
        statusDiv.textContent = `Restored last scan: ${currentScanId}`;
        updateHeaderScanInfo();

        const cachedHtml = localStorage.getItem("pcvp:lastServicesHtml");
        const cachedStats = localStorage.getItem("pcvp:lastStats");
        const cachedServices = localStorage.getItem("pcvp:lastServices");
        let hasCachedServices = false;

        if (cachedServices) {
        try {
          currentServices = JSON.parse(cachedServices);
          hasCachedServices = true;
        } catch (e) {}
      }

      if (cachedHtml) {
        document.querySelector("#services-table tbody").innerHTML = cachedHtml;
        // ✅ Re-attach click listeners after restoring HTML
        document.querySelector("#services-table tbody")
          .querySelectorAll(".btn-link")
          .forEach((btn) => btn.addEventListener("click", onDetailsClick));
        hasCachedServices = true;
      }


        if (cachedStats) {
          const stats = JSON.parse(cachedStats);
          document.getElementById("stat-hosts").textContent = stats.hosts || "0";
          document.getElementById("stat-services").textContent = stats.services || "0";
          document.getElementById("stat-critical").textContent = stats.critical || "0 / 0";
          document.getElementById("stat-weak-creds").textContent = stats.weak || "0";
          hasCachedServices = true;
        }

       const cachedGraphText = localStorage.getItem("pcvp:lastGraphText");
const cachedGraph = localStorage.getItem("pcvp:lastGraph");
let hasCachedGraph = false;

if (cachedGraphText) {
  document.getElementById("attack-graph-content").innerHTML = cachedGraphText;
  hasCachedGraph = true;
}

// ✅ Re-render vis.js network from cached graph data
if (cachedGraph) {
  try {
    const graph = JSON.parse(cachedGraph);
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];
    const graphContainer = document.getElementById("attack-graph-network");
    graphContainer.innerHTML = "";

    if (nodes.length && edges.length) {
      const visNodes = new vis.DataSet(
        nodes.map((n) => {
          let label = n.id, color = "#6b7280", shape = "ellipse";
          if (n.type === "host") { label = n.ip || n.id; color = "#1d4ed8"; shape = "box"; }
          else if (n.type === "service") {
            const level = (n.pcvp_level || "").toLowerCase();
            label = `${n.service || "svc"}\n${n.port || ""}/${n.protocol || ""}`;
            if (level === "critical") color = "#dc2626";
            else if (level === "high") color = "#f97316";
            else if (level === "medium") color = "#eab308";
            else if (level === "low") color = "#22c55e";
            else color = "#6b7280";
          } else if (n.type === "cve") { 
            label = n.cve_id || "CVE"; 
            color = "#0ea5e9"; 
            shape = "diamond"; 
          }
          return { id: n.id, label, color, shape, font: { color: "#e5e7eb", size: 12 } };
        })
      );

      const visEdges = new vis.DataSet(
        edges.map((e) => {
          let color = "#4b5563", dashes = false, label = "";
          if (e.relation === "runs") { label = "runs"; color = "#6b7280"; }
          else if (e.relation === "has_vulnerability") { label = "has CVE"; color = "#0ea5e9"; }
          else if (e.relation === "possible_chain") { label = "pivot"; color = "#f97316"; dashes = true; }
          return { from: e.from, to: e.to, color, dashes, arrows: "to", label, font: { align: "middle", color: "#9ca3af", size: 10 } };
        })
      );

      new vis.Network(graphContainer, { nodes: visNodes, edges: visEdges }, {
        autoResize: true,
        physics: { stabilization: true, barnesHut: { springLength: 120, springConstant: 0.01 } },
        interaction: { tooltipDelay: 200, hover: true },
        nodes: { borderWidth: 1 },
        layout: { improvedLayout: true },
      });
    }
  } catch (e) {
    console.error("Failed to restore attack graph network:", e);
  }
}

        const cachedGobuster = localStorage.getItem("pcvp:lastGobusterHtml");
        let hasCachedGobuster = false;
        if (cachedGobuster) {
          document.querySelector("#gobuster-table tbody").innerHTML = cachedGobuster;
          hasCachedGobuster = true;
        }

       if (!hasCachedServices) loadScanResults(currentScanId);
       if (!hasCachedGobuster) loadGobusterResults(currentScanId);
       if (!hasCachedGraph) loadAttackGraph(currentScanId);

        // ✅ Only poll if scan is not already completed
        const scanData = await fetch(`/scan/${currentScanId}`).then(r => r.json());
        if (scanData.status !== "completed") {
          pollScanStatus(currentScanId);
        } else {
          statusDiv.textContent = `Restored last scan: ${currentScanId}`;
          const reportBtn = document.getElementById("download-report-btn");
          if (reportBtn) reportBtn.disabled = false;
        }
      } else {
        localStorage.removeItem("pcvp:lastScanId");
        localStorage.removeItem("pcvp:lastServicesHtml");
        localStorage.removeItem("pcvp:lastStats");
        localStorage.removeItem("pcvp:lastServices");
        localStorage.removeItem("pcvp:lastGobusterHtml");
        localStorage.removeItem("pcvp:lastGraphText");
        resetOverview();
        setTableLoadingStates();
        updateHeaderScanInfo();
        statusDiv.textContent = "";
      }
    } catch (e) {
      localStorage.removeItem("pcvp:lastScanId");
      localStorage.removeItem("pcvp:lastServicesHtml");
      localStorage.removeItem("pcvp:lastStats");
      localStorage.removeItem("pcvp:lastGobusterHtml");
      localStorage.removeItem("pcvp:lastGraphText");
      resetOverview();
      setTableLoadingStates();
      updateHeaderScanInfo();
      statusDiv.textContent = "";
    }
  }

  const savedTarget = localStorage.getItem("pcvp:lastTarget");
  const savedExposure = localStorage.getItem("pcvp:lastExposure");
  if (savedTarget) document.getElementById("target").value = savedTarget;
  if (savedExposure) document.getElementById("exposure").value = savedExposure;

  const modal = document.getElementById("service-details-modal");
  const modalCloseBtn = document.getElementById("modal-close-btn");
  modalCloseBtn.addEventListener("click", () => (modal.style.display = "none"));
  modal.addEventListener("click", (e) => {
    if (e.target === modal) modal.style.display = "none";
  });

  const clearBtn = document.getElementById("clear-scans-btn");
  if (clearBtn) {
    clearBtn.addEventListener("click", async () => {
      if (!confirm("Clear persisted scan metadata from the server and local cache?")) return;
      try {
        const resp = await fetch("/scans/clear", { method: "POST" });
        if (!resp.ok) {
          const data = await resp.json().catch(() => ({}));
          alert(`Failed to clear persisted scans: ${data.detail || resp.status}`);
          return;
        }
        localStorage.removeItem("pcvp:lastScanId");
        localStorage.removeItem("pcvp:lastServicesHtml");
        localStorage.removeItem("pcvp:lastStats");
        localStorage.removeItem("pcvp:lastServices");
        localStorage.removeItem("pcvp:lastTarget");
        localStorage.removeItem("pcvp:lastExposure");
        localStorage.removeItem("pcvp:bootId");
        localStorage.removeItem("pcvp:lastGobusterHtml");
        localStorage.removeItem("pcvp:lastGraphText");
        currentScanId = null;
        resetOverview();
        setTableLoadingStates();
        updateHeaderScanInfo();
        document.getElementById("scan-status").textContent = "Cleared persisted scans.";
      } catch (err) {
        console.error(err);
        alert("Error clearing persisted scans (see console)");
      }
    });
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    // ✅ Clear cached UI from previous scan
    localStorage.removeItem("pcvp:lastServicesHtml");
    localStorage.removeItem("pcvp:lastStats");
    localStorage.removeItem("pcvp:lastServices");
    localStorage.removeItem("pcvp:lastGobusterHtml");
    localStorage.removeItem("pcvp:lastGraphText");

    // ✅ Clear remediation cache for old scan
    for (const key of Object.keys(localStorage)) {
      if (key.startsWith("pcvp:remediation:")) {
        localStorage.removeItem(key);
      }
    }
    const target = document.getElementById("target").value.trim();
    const exposure = document.getElementById("exposure").value;

    if (!target) {
      statusDiv.textContent = "Please enter a target.";
      return;
    }

    if (statusIntervalId !== null) {
      clearInterval(statusIntervalId);
      statusIntervalId = null;
    }

    resetOverview();
    setTableLoadingStates();

    const reportBtn = document.getElementById("download-report-btn");
    if (reportBtn) reportBtn.disabled = true;

    startBtn.disabled = true;
    statusDiv.textContent = "Starting scan...";

    try {
      const resp = await fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, exposure }),
      });

      if (!resp.ok) {
        statusDiv.textContent = `Error starting scan: ${resp.status}`;
        startBtn.disabled = false;
        return;
      }

      const data = await resp.json();
      currentScanId = data.scan_id;
      currentExposure = data.exposure || exposure;
      localStorage.setItem("pcvp:lastScanId", currentScanId);
      localStorage.setItem("pcvp:lastTarget", target);
      localStorage.setItem("pcvp:lastExposure", currentExposure);
      updateHeaderScanInfo();
      statusDiv.textContent = `Scan started (ID: ${currentScanId}). Waiting for completion...`;
      pollScanStatus(currentScanId);
    } catch (err) {
      console.error(err);
      statusDiv.textContent = "Error starting scan (check console/logs).";
      startBtn.disabled = false;
    }
  });
});

function resetOverview() {
  document.getElementById("stat-hosts").textContent = "0";
  document.getElementById("stat-services").textContent = "0";
  document.getElementById("stat-critical").textContent = "0 / 0";
  document.getElementById("stat-weak-creds").textContent = "0";
}

function setTableLoadingStates() {
  const servicesBody = document.querySelector("#services-table tbody");
  const gobBody = document.querySelector("#gobuster-table tbody");
  const agDiv = document.getElementById("attack-graph-content");
  const agNet = document.getElementById("attack-graph-network");
  servicesBody.innerHTML = `<tr><td colspan="8">Waiting for scan to complete...</td></tr>`;
  gobBody.innerHTML = `<tr><td colspan="3">Waiting for scan to complete...</td></tr>`;
  agDiv.textContent = "Waiting for scan to complete...";
  agNet.innerHTML = "";
}

function updateHeaderScanInfo() {
  const el = document.getElementById("header-scan-info");
  if (!currentScanId) { el.innerHTML = ""; return; }
  const badgeClass =
    currentExposure === "external" ? "badge-external" :
    currentExposure === "internal" ? "badge-internal" : "badge-auto";
  el.innerHTML = `
    <div style="text-align:right;">
      <div style="font-size:0.75rem; color:#9ca3af;">Current Scan ID</div>
      <div style="font-size:0.85rem;">${currentScanId}</div>
      <div style="margin-top:4px;">
        <span class="badge ${badgeClass}">${currentExposure || "auto"}</span>
      </div>
    </div>
  `;
}

function pollScanStatus(scanId) {
  const statusDiv = document.getElementById("scan-status");
  const startBtn = document.getElementById("start-scan-btn");
  const reportBtn = document.getElementById("download-report-btn");

  const doPoll = async () => {
    try {
      const resp = await fetch(`/scan/${scanId}`);
      if (!resp.ok) {
        statusDiv.textContent = `Error checking status: ${resp.status}`;
        clearInterval(statusIntervalId);
        statusIntervalId = null;
        startBtn.disabled = false;
        if (reportBtn) reportBtn.disabled = true;
        return;
      }

      const data = await resp.json();
      currentExposure = data.exposure || currentExposure;
      updateHeaderScanInfo();

      if (data.status === "completed") {
        // ✅ Fully done — stop polling and load everything
        clearInterval(statusIntervalId);
        statusIntervalId = null;
        startBtn.disabled = false;
        if (reportBtn) reportBtn.disabled = false;

        statusDiv.textContent = `Loading results...`;

        try {
          await Promise.all([
            loadScanResults(scanId).catch(e => {
              console.error("[LOADING] loadScanResults failed:", e);
              throw e;
            }),
            loadGobusterResults(scanId).catch(e => {
              console.error("[LOADING] loadGobusterResults failed:", e);
              throw e;
            }),
            loadAttackGraph(scanId).catch(e => {
              console.error("[LOADING] loadAttackGraph failed:", e);
              throw e;
            }),
          ]);
          statusDiv.textContent = `Scan fully completed (Nmap + Gobuster).`;
        } catch (loadErr) {
          console.error("[LOADING] Error loading results:", loadErr);
          statusDiv.textContent = `Scan completed but error loading results. Check console.`;
        }

      } else if (data.status === "failed") {
        clearInterval(statusIntervalId);
        statusIntervalId = null;
        startBtn.disabled = false;
        if (reportBtn) reportBtn.disabled = true;
        statusDiv.textContent = `Scan failed: ${data.message || "unknown error"}`;

      } else if (data.status === "nmap_done") {
        // ✅ Nmap done but gobuster still running
        if (data.gobuster_status === "completed") {
          statusDiv.textContent = `Gobuster completed. Finalizing...`;
        } else {
          statusDiv.textContent = `Nmap completed. Waiting for Gobuster to finish...`;
        }

      } else if (data.status === "running") {
        statusDiv.textContent = `Scan running... ${data.message || ""}`;

      } else {
        statusDiv.textContent = `Scan status: ${data.status} — ${data.message || ""}`;
      }

    } catch (err) {
      console.error("[POLL] Error in poll callback:", err);
      statusDiv.textContent = "Error checking status (see console).";
      clearInterval(statusIntervalId);
      statusIntervalId = null;
      startBtn.disabled = false;
      if (reportBtn) reportBtn.disabled = true;
    }
  };

  // Start polling
  statusIntervalId = setInterval(doPoll, 3000);
  // Also poll immediately
  doPoll();
}

async function loadScanResults(scanId) {
  const servicesBody = document.querySelector("#services-table tbody");
  servicesBody.innerHTML = `<tr><td colspan="8">Loading NVD/PCVP data...</td></tr>`;
  currentServices = [];

  try {
    const url = `/scan/${scanId}/nvd`;
    const resp = await fetch(url);
    
    if (!resp.ok) {
      const errorText = await resp.text().catch(() => "Unknown error");
      console.error("[loadScanResults] Server error:", resp.status, errorText);
      servicesBody.innerHTML = `<tr><td colspan="8">Server error: ${resp.status}</td></tr>`;
      return;
    }

    const data = await resp.json();
    const hosts = data.data.hosts || [];
    
    const rows = [];
    for (const host of hosts) {
      const ip = host.ip;
      for (const svc of host.services || []) {
        rows.push({ ip, ...svc });
      }
    }

    currentServices = rows;
    rows.sort((a, b) => (b.pcvp_score || 0) - (a.pcvp_score || 0));

    const hostCount = hosts.length;
    const serviceCount = rows.length;
    let criticalCount = 0, highCount = 0, weakCount = 0;
    for (const s of rows) {
      if (s.pcvp_level === "critical") criticalCount++;
      if (s.pcvp_level === "high") highCount++;
      if (s.weak_creds && s.weak_creds.found) weakCount++;
    }

    document.getElementById("stat-hosts").textContent = hostCount;
    document.getElementById("stat-services").textContent = serviceCount;
    document.getElementById("stat-critical").textContent = `${criticalCount} / ${highCount}`;
    document.getElementById("stat-weak-creds").textContent = weakCount;

   // ✅ Save stats immediately
localStorage.setItem("pcvp:lastStats", JSON.stringify({
  hosts: hostCount, services: serviceCount,
  critical: `${criticalCount} / ${highCount}`, weak: weakCount,
}));
localStorage.setItem("pcvp:lastServices", JSON.stringify(currentServices));

if (!rows.length) {
  servicesBody.innerHTML = `<tr><td colspan="8">No services detected for this scan.</td></tr>`;
  return;
}

servicesBody.innerHTML = "";
for (const svc of rows) {
  const tr = document.createElement("tr");
  const level = svc.pcvp_level || "informational";
  const badgeClass =
    level === "critical" ? "badge-critical" :
    level === "high" ? "badge-high" :
    level === "medium" ? "badge-medium" :
    level === "low" ? "badge-low" : "badge-info";
  const weakCredsText = svc.weak_creds && svc.weak_creds.found
    ? `${svc.weak_creds.protocol || ""} ${svc.weak_creds.username}:${svc.weak_creds.password}`
    : "None";
  const weakPillClass = svc.weak_creds && svc.weak_creds.found ? "pill pill-weak" : "pill";
  tr.innerHTML = `
    <td>${svc.ip || ""}</td>
    <td>${svc.port}</td>
    <td>${svc.service || ""}</td>
    <td>${(svc.product || "") + " " + (svc.version || "")}</td>
    <td><span class="badge ${badgeClass}">${level}</span></td>
    <td>${svc.pcvp_score ?? ""}</td>
    <td><span class="${weakPillClass}">${weakCredsText}</span></td>
    <td><button class="btn-link" data-ip="${svc.ip}" data-port="${svc.port}" data-proto="${svc.protocol}">Details</button></td>
  `;
  servicesBody.appendChild(tr);
}
servicesBody.querySelectorAll(".btn-link").forEach((btn) =>
  btn.addEventListener("click", onDetailsClick)
);

// ✅ Save HTML AFTER rows are fully rendered
localStorage.setItem("pcvp:lastServicesHtml", servicesBody.innerHTML);
} catch (err) {
  console.error("[loadScanResults] CATCH ERROR:", err.name, err.message);
  console.error("[loadScanResults] Full error:", err);
  servicesBody.innerHTML = `<tr><td colspan="8">Error loading NVD/PCVP data: ${err.message}</td></tr>`;
}
}
async function loadGobusterResults(scanId) {
  const gobBody = document.querySelector("#gobuster-table tbody");
  gobBody.innerHTML = `<tr><td colspan="3">Loading Gobuster results...</td></tr>`;

  try {
    const resp = await fetch(`/webscan/${scanId}/results`);
    if (!resp.ok) {
      gobBody.innerHTML = `<tr><td colspan="3">No Gobuster results yet or error: ${resp.status}</td></tr>`;
      return;
    }

    const data = await resp.json();
    const results = data.results || [];
    const error = data.error || null;

    if (error && !results.length) {
      gobBody.innerHTML = `<tr><td colspan="3">Gobuster failed: ${escapeHtml(error)}</td></tr>`;
      return;
    }

    if (!results.length) {
      gobBody.innerHTML = `<tr><td colspan="3">No directories found.</td></tr>`;
      return;
    }

    gobBody.innerHTML = "";
    for (const r of results) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${r.path}</td>
        <td>${r.status}</td>
        <td>${r.size ?? ""}</td>
      `;
      gobBody.appendChild(tr);
    }
    localStorage.setItem("pcvp:lastGobusterHtml", gobBody.innerHTML);
  } catch (err) {
    console.error(err);
    gobBody.innerHTML = `<tr><td colspan="3">Error loading Gobuster results (see console).</td></tr>`;
  }
}

async function loadAttackGraph(scanId) {
  const textContainer = document.getElementById("attack-graph-content");
  const graphContainer = document.getElementById("attack-graph-network");
  textContainer.textContent = "Loading attack graph...";
  graphContainer.innerHTML = "";

  try {
    const resp = await fetch(`/scan/${scanId}/attack-graph`);
    if (!resp.ok) {
      const errorText = await resp.text().catch(() => "Unknown error");
      console.error("[loadAttackGraph] Error response:", errorText);
      textContainer.textContent = `Error loading attack graph: ${resp.status}`;
      return;
    }

    const data = await resp.json();
    const graph = data.graph || {};
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];

    if (!nodes.length || !edges.length) {
      textContainer.textContent = "No attack paths identified for this scan.";
      return;
    }

    const nodeById = {};
    nodes.forEach((n) => (nodeById[n.id] = n));

    const visNodes = new vis.DataSet(
      nodes.map((n) => {
        let label = n.id, color = "#6b7280", shape = "ellipse";
        if (n.type === "host") { label = n.ip || n.id; color = "#1d4ed8"; shape = "box"; }
        else if (n.type === "service") {
          const level = (n.pcvp_level || "").toLowerCase();
          label = `${n.service || "svc"}\n${n.port || ""}/${n.protocol || ""}`;
          if (level === "critical") color = "#dc2626";
          else if (level === "high") color = "#f97316";
          else if (level === "medium") color = "#eab308";
          else if (level === "low") color = "#22c55e";
          else color = "#6b7280";
        } else if (n.type === "cve") { label = n.cve_id || "CVE"; color = "#0ea5e9"; shape = "diamond"; }
        return { id: n.id, label, color, shape, font: { color: "#e5e7eb", size: 12 } };
      })
    );

    const visEdges = new vis.DataSet(
      edges.map((e) => {
        let color = "#4b5563", dashes = false, label = "";
        if (e.relation === "runs") { label = "runs"; color = "#6b7280"; }
        else if (e.relation === "has_vulnerability") { label = "has CVE"; color = "#0ea5e9"; }
        else if (e.relation === "possible_chain") { label = "pivot"; color = "#f97316"; dashes = true; }
        return { from: e.from, to: e.to, color, dashes, arrows: "to", label, font: { align: "middle", color: "#9ca3af", size: 10 } };
      })
    );

    new vis.Network(graphContainer, { nodes: visNodes, edges: visEdges }, {
      autoResize: true,
      physics: { stabilization: true, barnesHut: { springLength: 120, springConstant: 0.01 } },
      interaction: { tooltipDelay: 200, hover: true },
      nodes: { borderWidth: 1 },
      layout: { improvedLayout: true },
    });

    const hostServices = {};
    edges.forEach((e) => {
      if (e.relation === "runs") {
        if (!hostServices[e.from]) hostServices[e.from] = [];
        hostServices[e.from].push(e.to);
      }
    });

    const chains = [];
    for (const [hostId, serviceIds] of Object.entries(hostServices)) {
      const hostNode = nodeById[hostId];
      const hostIp = hostNode && hostNode.ip ? hostNode.ip : hostId;
      for (const sid of serviceIds) {
        const svc = nodeById[sid];
        if (!svc) continue;
        const level = (svc.pcvp_level || "").toLowerCase();
        const score = svc.pcvp_score || 0;
        if (!(level === "critical" || level === "high")) continue;
        const cveEdges = edges.filter((e) => e.from === sid && e.relation === "has_vulnerability");
        const cveIds = cveEdges.map((e) => nodeById[e.to]).filter(Boolean).map((c) => c.cve_id || c.id || c.name).filter(Boolean);
        const chainEdges = edges.filter((e) => e.from === sid && e.relation === "possible_chain");
        const nextServices = chainEdges.map((e) => nodeById[e.to]).filter(Boolean).map((ns) => `${ns.service || "service"} on ${ns.ip || hostIp}:${ns.port}`);
        chains.push({ hostIp, service: svc.service || "service", port: svc.port, level, score, cves: cveIds, nextServices });
      }
    }
if (!chains.length) {
  textContainer.textContent = "No high/critical attack paths identified. Lower-risk services may exist but no strong chains.";
} else {
  let html = "<ul>";
  for (const ch of chains) {
    html += "<li style='margin-bottom:6px;'>";
    html += `<strong>${ch.service}</strong> on <strong>${ch.hostIp}:${ch.port}</strong> `;
    html += `(PCVP: ${ch.level.toUpperCase()} score ${ch.score})`;
    if (ch.cves.length) { html += "<br><span style='color:#9ca3af;'>Exploitable via:</span> " + ch.cves.map((id) => `<code>${id}</code>`).join(", "); }
    if (ch.nextServices.length) { html += "<br><span style='color:#9ca3af;'>Potential pivot to:</span> " + ch.nextServices.join(", "); }
    html += "</li>";
  }
  html += "</ul>";
  textContainer.innerHTML = html;
}

// ✅ Always save cache regardless of chains length
localStorage.setItem("pcvp:lastGraph", JSON.stringify(graph));
localStorage.setItem("pcvp:lastGraphText", textContainer.innerHTML || textContainer.textContent);
  } catch (err) {
    console.error(err);
    textContainer.textContent = "Error building attack graph (see console).";
  }
}

async function loadLLMRemediation(scanId, svc) {
  const el = document.getElementById("llm-remediation");
  if (!el) return;

  // ✅ Check cache first
  const cacheKey = `pcvp:remediation:${scanId}:${svc.ip}:${svc.port}:${svc.protocol || "tcp"}`;
  const cached = localStorage.getItem(cacheKey);
  if (cached) {
    el.innerHTML = cached;
    return;
  }

  el.innerHTML = `<div style="color:#9ca3af;">Generating remediation...</div>`;

  try {
    const resp = await fetch(`/scan/${scanId}/remediation`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: scanId, ip: svc.ip, port: svc.port, protocol: svc.protocol || "tcp" }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      el.innerHTML = `<div style="color:#fca5a5;">Failed: ${escapeHtml(data.detail || `HTTP ${resp.status}`)}</div>`;
      return;
    }
    const r = data.remediation || {};
    const steps = Array.isArray(r.steps) ? r.steps : [];
    const verification = Array.isArray(r.verification) ? r.verification : [];
    const refs = Array.isArray(r.references) ? r.references : [];

    const html = `
      <div><strong>Summary:</strong> ${escapeHtml(r.summary || "")}</div>
      <div><strong>Priority:</strong> ${escapeHtml(r.priority || "")}</div>
      ${steps.length ? `<div class="section-title">Recommended Steps</div><ul>${steps.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ul>` : `<div style="color:#9ca3af; margin-top:6px;">No steps returned.</div>`}
      ${verification.length ? `<div class="section-title">Verification</div><ul>${verification.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ul>` : ""}
      ${refs.length ? `<div class="section-title">References</div><ul>${refs.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ul>` : ""}
    `;

    el.innerHTML = html;
    // ✅ Save to cache
    localStorage.setItem(cacheKey, html);
  } catch (err) {
    console.error(err);
    el.innerHTML = `<div style="color:#fca5a5;">Error generating remediation (see console).</div>`;
  }
}
function onDetailsClick(e) {
  const ip = e.target.getAttribute("data-ip");
  const port = parseInt(e.target.getAttribute("data-port"), 10);
  const proto = e.target.getAttribute("data-proto") || "tcp";
  const svc = currentServices.find((s) => s.ip === ip && s.port === port && (s.protocol || "tcp") === proto);
  if (!svc) return;

  const modal = document.getElementById("service-details-modal");
  const title = document.getElementById("modal-title");
  const body = document.getElementById("modal-body");
  title.textContent = `${svc.service || ""} on ${svc.ip}:${svc.port}/${svc.protocol}`;

  const reasons = svc.pcvp_reasons || [];
  const nvd = svc.nvd || {};
  const cves = nvd.cves || nvd.CVEs || [];

  let html = "";
  html += `<div><strong>Product:</strong> ${escapeHtml(svc.product || "")} ${escapeHtml(svc.version || "")}</div>`;
  html += `<div><strong>Exposure:</strong> ${escapeHtml(currentExposure || "auto")}</div>`;
  html += `<div><strong>PCVP:</strong> ${escapeHtml(svc.pcvp_level || "")} (score ${svc.pcvp_score ?? ""})</div>`;
  if (svc.weak_creds && svc.weak_creds.found) {
    html += `<div style="margin-top:4px;"><strong>Weak Credentials:</strong> ${escapeHtml(`${svc.weak_creds.protocol || ""} ${svc.weak_creds.username}:${svc.weak_creds.password}`)}</div>`;
  }
  html += `<div class="section-title">Why this is prioritized</div>`;
  if (reasons.length) { html += "<ul>"; for (const r of reasons) html += `<li>${escapeHtml(r)}</li>`; html += "</ul>"; }
  else { html += "<div>No reasons available.</div>"; }
  html += `<div class="section-title">Mapped CVEs</div>`;
  if (cves.length) {
    html += "<ul>";
    for (const c of cves) {
      const id = c.cve_id || c.id || "Unknown";
      const sev = c.severity || c.SEVERITY || "Unknown";
      const score = c.score || c.cvss || c.CVSS || "";
      html += `<li>${escapeHtml(id)} (severity: ${escapeHtml(sev)}, score: ${escapeHtml(score)})</li>`;
    }
    html += "</ul>";
  } else { html += "<div>No CVEs mapped for this service.</div>"; }
  html += `<div class="section-title">Remediation</div>`;
  html += `<div id="llm-remediation" style="margin-top:6px; color:#9ca3af;">Not generated yet.</div>`;
  body.innerHTML = html;
  modal.style.display = "flex";
  if (currentScanId) loadLLMRemediation(currentScanId, svc);
}

function escapeHtml(str) {
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function downloadReport() {
  if (!currentScanId) { alert("Run a scan first, then download the report."); return; }
  window.location.href = `/scan/${currentScanId}/report.pdf`;
}