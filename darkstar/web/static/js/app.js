// ============================================================================
// STATE MANAGEMENT
// ============================================================================

const state = {
    authenticated: document.body.dataset.authenticated === "true",
    organization: document.body.dataset.organization || "",
    orgDb: document.body.dataset.orgDb || "",
    currentTab: "dashboard",
    vulnFilters: {
        severity: "",
        host: "",
        tool: "",
        page: 0,
        limit: 50,
        groupBy: "none",
    },
    vulnTotal: 0,
    activeScanId: null,
    ws: null,
    wsPingTimer: null,
    debugPollTimer: null,
    debugLogs: [],
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value == null ? "" : String(value);
    return div.innerHTML;
}

async function requestJson(url, options = {}) {
    const response = await fetch(url, {
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        ...options,
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(payload.detail || "Request failed");
    }
    return payload;
}

function setAuthUI() {
    const loginPanel = document.getElementById("loginScreen");
    const dashboardPanel = document.getElementById("mainDashboard");
    const logoutBtn = document.getElementById("logoutBtn");
    
    if (loginPanel) loginPanel.classList.toggle("hidden", state.authenticated);
    if (dashboardPanel) dashboardPanel.classList.toggle("hidden", !state.authenticated);
    if (logoutBtn) logoutBtn.classList.toggle("hidden", !state.authenticated);
}

// ============================================================================
// TAB MANAGEMENT
// ============================================================================

// Returns a Promise that resolves once the tab's data has loaded.
function switchTab(tabName) {
    document.querySelectorAll(".tab-panel").forEach(tab => tab.classList.remove("active"));
    document.querySelectorAll(".tab-button").forEach(btn => btn.classList.remove("active"));

    const tabEl = document.getElementById(`${tabName}-tab`);
    if (tabEl) tabEl.classList.add("active");

    const tabButton = document.querySelector(`[data-tab="${tabName}"]`);
    if (tabButton) tabButton.classList.add("active");

    state.currentTab = tabName;

    if (tabName === "vulns")    return loadFilteredVulnerabilities();
    if (tabName === "targets")  return loadTargetsView();
    if (tabName === "surface")  return loadAttackSurfaceView();
    if (tabName === "debug")    return loadDebugPanel();
    return Promise.resolve();
}

// ============================================================================
// DASHBOARD TAB
// ============================================================================

function renderSeverityList(breakdown) {
    const target = document.getElementById("severityList");
    const entries = Object.entries(breakdown || {});
    if (!entries.length) {
        target.innerHTML = "<span>No findings yet</span>";
        return;
    }

    target.innerHTML = entries
        .map(([severity, count]) => `<span class="severity-${escapeHtml(severity)}">${escapeHtml(severity)}: ${count}</span>`)
        .join("");
}

function renderActiveScans(items) {
    const container = document.getElementById("activeScansList");
    if (!container) return;
    const active = items.filter(s => s.status === "running" || s.status === "queued");
    if (!active.length) {
        container.innerHTML = '<p class="empty-state">No active scans</p>';
        return;
    }
    container.innerHTML = active.map(scan => `
        <div class="scan-item">
            <div class="scan-item-header">${escapeHtml(scan.scan_name || "-")}</div>
            <div class="scan-item-detail">
                Mode: ${escapeHtml(scan.scan_mode || "-")} &middot;
                <span class="status-${escapeHtml(scan.status)}">${escapeHtml(scan.status)}</span>
            </div>
        </div>
    `).join("");
}

function renderScans(items) {
    const target = document.getElementById("scanRows");
    if (!items.length) {
        target.innerHTML = '<tr><td colspan="5">No scans started yet.</td></tr>';
        return;
    }

    target.innerHTML = items
        .map((scan) => {
            const status = (scan.status || "unknown").toLowerCase();
            return `
                <tr>
                    <td>${scan.id}</td>
                    <td>${escapeHtml(scan.scan_name || "-")}</td>
                    <td>${escapeHtml(scan.scan_mode || "-")}</td>
                    <td class="status-${escapeHtml(status)}">${escapeHtml(scan.status || "unknown")}</td>
                    <td>${escapeHtml(scan.created_at || "-")}</td>
                </tr>
            `;
        })
        .join("");
}

async function refreshDashboard() {
    if (!state.authenticated) return;

    try {
        const [me, stats, scans] = await Promise.all([
            requestJson("/api/me"),
            requestJson("/api/stats"),
            requestJson("/api/scans?limit=50"),
        ]);

        if (me.organization) {
            state.organization = me.organization;
            state.orgDb = me.org_db;
            const topOrgName = document.getElementById("topOrgName");
            if (topOrgName) {
                topOrgName.textContent = me.organization;
            }
        }

        document.getElementById("statTotal").textContent = stats.total_vulnerabilities ?? 0;
        document.getElementById("statRunning").textContent = stats.running_scans ?? 0;
        renderSeverityList(stats.severity_breakdown || {});
        renderScans(scans.items || []);
        renderActiveScans(scans.items || []);
    } catch (error) {
        console.error("Dashboard refresh failed:", error);
    }
}

// ============================================================================
// VULNERABILITIES TAB
// ============================================================================

async function loadFilterOptions() {
    try {
        const [hostsRes, toolsRes] = await Promise.all([
            requestJson("/api/filters/hosts"),
            requestJson("/api/filters/tools"),
        ]);

        // Populate host filter
        const hostSelect = document.getElementById("filterHost");
        hostsRes.items.forEach(host => {
            const opt = document.createElement("option");
            opt.value = host;
            opt.textContent = host;
            hostSelect.appendChild(opt);
        });

        // Populate tool filter
        const toolSelect = document.getElementById("filterTool");
        toolsRes.items.forEach(tool => {
            const opt = document.createElement("option");
            opt.value = tool;
            opt.textContent = tool;
            toolSelect.appendChild(opt);
        });
    } catch (error) {
        console.error("Failed to load filter options:", error);
    }
}

async function loadFilteredVulnerabilities() {
    try {
        const params = new URLSearchParams({
            limit: state.vulnFilters.limit,
            offset: state.vulnFilters.page * state.vulnFilters.limit,
        });

        if (state.vulnFilters.severity) params.append("severity", state.vulnFilters.severity);
        if (state.vulnFilters.host) params.append("host", state.vulnFilters.host);
        if (state.vulnFilters.tool) params.append("tool", state.vulnFilters.tool);

        const result = await requestJson(`/api/vulnerabilities/filtered?${params}`);
        state.vulnTotal = result.total;

        let items = result.items || [];

        // Group if needed
        if (state.vulnFilters.groupBy !== "none") {
            items = groupVulnerabilities(items, state.vulnFilters.groupBy);
        }

        renderFilteredVulnerabilities(items);
        updatePaginationInfo();
    } catch (error) {
        console.error("Failed to load filtered vulnerabilities:", error);
        document.getElementById("vulnRows").innerHTML = 
            '<tr><td colspan="6">Error loading vulnerabilities.</td></tr>';
    }
}

function groupVulnerabilities(items, groupBy) {
    const grouped = {};

    items.forEach(item => {
        const key = groupBy === "severity" 
            ? (item.severity || "unknown").toUpperCase()
            : groupBy === "host"
            ? (item.host || "unknown")
            : (item.tool || "unknown");

        if (!grouped[key]) {
            grouped[key] = { group: key, items: [] };
        }
        grouped[key].items.push(item);
    });

    return Object.values(grouped);
}

function renderFilteredVulnerabilities(items) {
    const target = document.getElementById("vulnRows");

    if (state.vulnFilters.groupBy !== "none") {
        // Render grouped
        target.innerHTML = items.map(group => {
            const rows = group.items.map(item => {
                const sev = (item.severity || "unknown").toLowerCase();
                return `
                    <tr class="vuln-row-${escapeHtml(sev)}">
                        <td>${item.id}</td>
                        <td class="severity-${escapeHtml(sev)}">${escapeHtml(item.severity || "unknown")}</td>
                        <td>${escapeHtml(item.title || "-")}</td>
                        <td>${escapeHtml(item.host || "-")}</td>
                        <td>${escapeHtml(item.tool || "-")}</td>
                        <td>${escapeHtml(item.cve || "-")}</td>
                    </tr>
                `;
            }).join("");

            return `
                <tr style="background: rgba(109, 224, 255, 0.1);">
                    <td colspan="6" style="font-weight: 700; padding: 8px;">${group.group}</td>
                </tr>
                ${rows}
            `;
        }).join("");
    } else {
        // Render flat
        if (!items.length) {
            target.innerHTML = '<tr><td colspan="6">No vulnerabilities match filters.</td></tr>';
            return;
        }

        target.innerHTML = items.map(item => {
            const sev = (item.severity || "unknown").toLowerCase();
            return `
                <tr class="vuln-row-${escapeHtml(sev)}">
                    <td>${item.id}</td>
                    <td class="severity-${escapeHtml(sev)}">${escapeHtml(item.severity || "unknown")}</td>
                    <td>${escapeHtml(item.title || "-")}</td>
                    <td>${escapeHtml(item.host || "-")}</td>
                    <td>${escapeHtml(item.tool || "-")}</td>
                    <td>${escapeHtml(item.cve || "-")}</td>
                </tr>
            `;
        }).join("");
    }
}

function updatePaginationInfo() {
    const pageNum = state.vulnFilters.page + 1;
    const totalPages = Math.ceil(state.vulnTotal / state.vulnFilters.limit) || 1;
    
    document.getElementById("pageInfo").textContent =
        `Page ${pageNum} of ${totalPages} (${state.vulnTotal} total)`;
    
    document.getElementById("prevPageBtn").disabled = state.vulnFilters.page === 0;
    document.getElementById("nextPageBtn").disabled = pageNum >= totalPages;
    
    document.getElementById("resultCount").textContent = 
        `${state.vulnTotal} total vulnerabilities`;
}

// ============================================================================
// TARGETS TAB
// ============================================================================

async function loadTargetsView() {
    try {
        const vulns = await requestJson("/api/vulnerabilities?limit=1000");
        const hostMap = {};

        // Build host statistics
        (vulns.items || []).forEach(vuln => {
            if (!vuln.host) return;
            if (!hostMap[vuln.host]) {
                hostMap[vuln.host] = {
                    host: vuln.host,
                    count: 0,
                    maxSeverity: "info",
                    lastSeen: vuln.id,
                };
            }
            hostMap[vuln.host].count++;
        });

        const severity_order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        Object.values(hostMap).forEach(host => {
            (vulns.items || []).forEach(vuln => {
                if (vuln.host === host.host) {
                    const sev = (vuln.severity || "info").toLowerCase();
                    const sevOrder = severity_order[sev] ?? 5;
                    const maxOrder = severity_order[host.maxSeverity] ?? 5;
                    if (sevOrder < maxOrder) {
                        host.maxSeverity = sev;
                    }
                }
            });
        });

        const rows = Object.values(hostMap)
            .sort((a, b) => a.host.localeCompare(b.host))
            .map(host => `
                <tr>
                    <td>${escapeHtml(host.host)}</td>
                    <td>${host.count}</td>
                    <td class="severity-${escapeHtml(host.maxSeverity)}">${escapeHtml(host.maxSeverity)}</td>
                </tr>
            `).join("");

        document.getElementById("targetsRows").innerHTML = rows || 
            '<tr><td colspan="3">No targets discovered yet.</td></tr>';
    } catch (error) {
        console.error("Failed to load targets:", error);
    }
}

// ============================================================================
// ATTACK SURFACE TAB
// ============================================================================

async function loadAttackSurfaceView() {
    try {
        const vulns = await requestJson("/api/vulnerabilities?limit=1000");
        const items = vulns.items || [];

        // Calculate metrics
        const uniqueHosts = new Set(items.map(v => v.host).filter(h => h));
        const criticalCount = items.filter(v => (v.severity || "").toLowerCase() === "critical").length;
        let avgCvss = 0;
        let cvssCount = 0;

        items.forEach(item => {
            if (item.cvss) {
                avgCvss += parseFloat(item.cvss);
                cvssCount++;
            }
        });

        avgCvss = cvssCount > 0 ? (avgCvss / cvssCount).toFixed(1) : 0;

        // Update metrics
        document.getElementById("totalServices").textContent = uniqueHosts.size;
        document.getElementById("criticalAssets").textContent = criticalCount;
        document.getElementById("exploitableIssues").textContent = items.filter(v => v.cve).length;
        document.getElementById("meanCvss").textContent = avgCvss;

        // Build top services
        const serviceMap = {};
        items.forEach(item => {
            const key = `${item.host}|${item.tool}`;
            if (!serviceMap[key]) {
                serviceMap[key] = {
                    host: item.host || "unknown",
                    tool: item.tool || "unknown",
                    count: 0,
                    cvssScores: [],
                };
            }
            serviceMap[key].count++;
            if (item.cvss) serviceMap[key].cvssScores.push(parseFloat(item.cvss));
        });

        const rows = Object.values(serviceMap)
            .sort((a, b) => b.count - a.count)
            .slice(0, 10)
            .map(svc => {
                const avgCvss = svc.cvssScores.length > 0 
                    ? (svc.cvssScores.reduce((a, b) => a + b) / svc.cvssScores.length).toFixed(2)
                    : "-";
                return `
                    <tr>
                        <td>${escapeHtml(svc.host)}</td>
                        <td>${escapeHtml(svc.tool)}</td>
                        <td>${svc.count}</td>
                        <td>${avgCvss}</td>
                    </tr>
                `;
            }).join("");

        document.getElementById("topServicesRows").innerHTML = rows ||
            '<tr><td colspan="4">No services found.</td></tr>';
    } catch (error) {
        console.error("Failed to load attack surface:", error);
    }
}

// ============================================================================
// DEBUG PANEL
// ============================================================================

async function loadDebugPanel() {
    try {
        // Load list of scans for debug selection
        const scans = await requestJson("/api/scans?limit=100");
        const select = document.getElementById("debugScanSelect");
        
        select.innerHTML = '<option value="">Select a scan...</option>';
        (scans.items || []).forEach(scan => {
            const opt = document.createElement("option");
            opt.value = scan.id;
            opt.textContent = `[${scan.id}] ${scan.scan_name} (${scan.status})`;
            select.appendChild(opt);
        });
    } catch (error) {
        console.error("Failed to load debug panel:", error);
    }
}

async function loadScanLogs(scanId) {
    if (!scanId) return;

    try {
        state.activeScanId = scanId;
        stopDebugPolling();
        if (state.ws) {
            state.ws.__manualClose = true;
            state.ws.close();
        }

        const logs = await requestJson(`/api/scans/${scanId}/logs?limit=1000`);
        state.debugLogs = (logs.items || []).map(log => escapeHtml(log.message || ""));
        renderDebugLogs();

        connectDebugWebSocket(scanId);
    } catch (error) {
        console.error("Failed to load scan logs:", error);
    }
}

function stopDebugPolling() {
    if (state.debugPollTimer) {
        clearInterval(state.debugPollTimer);
        state.debugPollTimer = null;
    }
}

function startDebugPolling(scanId) {
    stopDebugPolling();
    state.debugPollTimer = setInterval(async () => {
        try {
            const logs = await requestJson(`/api/scans/${scanId}/logs?limit=1000`);
            state.debugLogs = (logs.items || []).map(log => escapeHtml(log.message || ""));
            renderDebugLogs();
        } catch (error) {
            console.debug("Debug polling failed:", error.message);
        }
    }, 3000);
}

function connectDebugWebSocket(scanId) {
    if (state.ws) {
        state.ws.__manualClose = true;
        state.ws.close();
    }
    if (state.wsPingTimer) {
        clearInterval(state.wsPingTimer);
        state.wsPingTimer = null;
    }

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/scan/${scanId}`;

    let reconnectAttempts = 0;
    const maxReconnectAttempts = 3;
    let fallbackStarted = false;

    function attemptConnect() {
        try {
            console.log(`[WebSocket] Attempting connection (attempt ${reconnectAttempts + 1}/${maxReconnectAttempts})...`);
            state.ws = new WebSocket(wsUrl);
            const socket = state.ws;
            socket.__manualClose = false;

            socket.onopen = () => {
                console.log("[WebSocket] Connected successfully");
                reconnectAttempts = 0;
                fallbackStarted = false;
                stopDebugPolling();
                appendDebugLog("[✓] Connected to debug stream", "info");

                // Keep the socket alive on infrastructures that aggressively close idle connections.
                state.wsPingTimer = setInterval(() => {
                    if (socket.readyState === WebSocket.OPEN) {
                        socket.send("ping");
                    }
                }, 20000);
            };

            socket.onmessage = (event) => {
                const msg = JSON.parse(event.data);
                if (msg.type === "log") {
                    appendDebugLog(msg.message, msg.level);
                } else if (msg.type === "completed" || msg.type === "error") {
                    appendDebugLog(`[${msg.type.toUpperCase()}] ${msg.message}`, msg.type);
                }
            };

            socket.onerror = (error) => {
                console.error("[WebSocket] Error:", error);
            };

            socket.onclose = () => {
                console.log("[WebSocket] Closed");
                if (state.wsPingTimer) {
                    clearInterval(state.wsPingTimer);
                    state.wsPingTimer = null;
                }

                if (socket.__manualClose) {
                    return;
                }

                if (reconnectAttempts < maxReconnectAttempts) {
                    reconnectAttempts++;
                    const delay = Math.min(1000 * Math.pow(2, reconnectAttempts - 1), 10000); // Exponential backoff, max 10s
                    appendDebugLog(`[WARN] WebSocket disconnected, retrying in ${Math.floor(delay / 1000)}s...`, "warning");
                    console.log(`[WebSocket] Reconnecting in ${delay}ms...`);
                    setTimeout(attemptConnect, delay);
                } else {
                    if (!fallbackStarted) {
                        fallbackStarted = true;
                        appendDebugLog("[WARN] WebSocket unavailable. Switched to polling logs every 3s.", "warning");
                        startDebugPolling(scanId);
                    }
                }
            };
        } catch (err) {
            console.error("[WebSocket] Connection error:", err);
            if (!fallbackStarted) {
                fallbackStarted = true;
                appendDebugLog("[WARN] WebSocket unavailable. Switched to polling logs every 3s.", "warning");
                startDebugPolling(scanId);
            }
        }
    }

    attemptConnect();
}

function appendDebugLog(message, level = "info") {
    state.debugLogs.push(escapeHtml(message));
    renderDebugLogs();
}

function renderDebugLogs() {
    const output = document.getElementById("debugOutput");
    output.innerHTML = state.debugLogs
        .slice(-500) // Keep last 500 lines
        .map(line => `<div class="log-line">${line}</div>`)
        .join("");

    // Auto-scroll to bottom
    output.scrollTop = output.scrollHeight;
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================

// Tab switching
document.querySelectorAll(".tab-button").forEach(btn => {
    btn.addEventListener("click", () => {
        switchTab(btn.dataset.tab);
    });
});

// Login form
document.getElementById("loginForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const loginMessage = document.getElementById("loginMessage");
    loginMessage.textContent = "";

    const organization = document.getElementById("orgInput").value.trim();
    const password = document.getElementById("passwordInput").value;

    try {
        const result = await requestJson("/api/auth/login", {
            method: "POST",
            body: JSON.stringify({ organization, password }),
        });
        state.authenticated = true;
        state.organization = result.organization;
        state.orgDb = result.org_db;
        setAuthUI();
        loginMessage.textContent = result.created
            ? "Organization provisioned and logged in."
            : "Logged in successfully.";
        await refreshDashboard();
        await loadFilterOptions();
    } catch (error) {
        loginMessage.textContent = error.message;
    }
});

// Logout
document.getElementById("logoutBtn").addEventListener("click", async () => {
    try {
        await requestJson("/api/auth/logout", { method: "POST" });
    } finally {
        state.authenticated = false;
        state.organization = "";
        state.orgDb = "";
        setAuthUI();
    }
});

// Scan form
document.getElementById("scanForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const scanMessage = document.getElementById("scanMessage");
    scanMessage.textContent = "";

    const targets = document.getElementById("targetsInput").value.trim();
    const mode = document.getElementById("modeInput").value;
    const scanner = document.getElementById("scannerInput").value;
    const scanName = document.getElementById("scanNameInput").value.trim();
    const bruteforce = document.getElementById("bruteforceInput").checked;

    if (!mode && !scanner) {
        scanMessage.textContent = "Select either a scan mode or an individual scanner.";
        return;
    }

    if (mode && scanner) {
        scanMessage.textContent = "Choose mode OR scanner, not both.";
        return;
    }

    try {
        const result = await requestJson("/api/scans/start", {
            method: "POST",
            body: JSON.stringify({
                targets,
                mode: mode ? Number(mode) : null,
                scanner: scanner || null,
                scan_name: scanName || null,
                bruteforce,
                bruteforce_timeout: 300,
            }),
        });
        scanMessage.textContent = "Scan queued successfully. Check Debug Panel for live output.";
        // Switch to debug tab and wait for its scan list to populate, then select
        // the new scan so the select reflects the correct entry.
        await switchTab("debug");
        document.getElementById("debugScanSelect").value = String(result.scan_id);
        await loadScanLogs(result.scan_id);
        await refreshDashboard();
    } catch (error) {
        scanMessage.textContent = error.message;
    }
});

// Mode/scanner are mutually exclusive in backend contract.
document.getElementById("modeInput").addEventListener("change", (e) => {
    if (e.target.value) {
        document.getElementById("scannerInput").value = "";
    }
});

document.getElementById("scannerInput").addEventListener("change", (e) => {
    if (e.target.value) {
        document.getElementById("modeInput").value = "";
    }
});

// Filter controls
document.getElementById("filterSeverity").addEventListener("change", (e) => {
    state.vulnFilters.severity = e.target.value;
    state.vulnFilters.page = 0;
    loadFilteredVulnerabilities();
});

document.getElementById("filterHost").addEventListener("change", (e) => {
    state.vulnFilters.host = e.target.value;
    state.vulnFilters.page = 0;
    loadFilteredVulnerabilities();
});

document.getElementById("filterTool").addEventListener("change", (e) => {
    state.vulnFilters.tool = e.target.value;
    state.vulnFilters.page = 0;
    loadFilteredVulnerabilities();
});

document.getElementById("groupBySelect").addEventListener("change", (e) => {
    state.vulnFilters.groupBy = e.target.value;
    loadFilteredVulnerabilities();
});

document.getElementById("clearFiltersBtn").addEventListener("click", () => {
    state.vulnFilters = {
        severity: "",
        host: "",
        tool: "",
        page: 0,
        limit: 50,
        groupBy: "none",
    };
    document.getElementById("filterSeverity").value = "";
    document.getElementById("filterHost").value = "";
    document.getElementById("filterTool").value = "";
    document.getElementById("groupBySelect").value = "none";
    loadFilteredVulnerabilities();
});

// Pagination
document.getElementById("prevPageBtn").addEventListener("click", () => {
    if (state.vulnFilters.page > 0) {
        state.vulnFilters.page--;
        loadFilteredVulnerabilities();
    }
});

document.getElementById("nextPageBtn").addEventListener("click", () => {
    const maxPage = Math.ceil(state.vulnTotal / state.vulnFilters.limit);
    if (state.vulnFilters.page < maxPage - 1) {
        state.vulnFilters.page++;
        loadFilteredVulnerabilities();
    }
});

// Debug panel
document.getElementById("debugScanSelect").addEventListener("change", (e) => {
    state.debugLogs = [];
    loadScanLogs(e.target.value);
});

document.getElementById("refreshLogsBtn").addEventListener("click", () => {
    if (state.activeScanId) {
        loadScanLogs(state.activeScanId);
    }
});

document.getElementById("clearLogsBtn").addEventListener("click", () => {
    state.debugLogs = [];
    document.getElementById("debugOutput").innerHTML = "";
});

// ============================================================================
// INITIALIZATION
// ============================================================================

setAuthUI();
if (state.authenticated) {
    refreshDashboard();
    loadFilterOptions();
    setInterval(refreshDashboard, 20000);
}
