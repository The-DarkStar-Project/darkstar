// ============================================================================
// STATE MANAGEMENT
// ============================================================================

const state = {
    authenticated: document.body.dataset.authenticated === "true",
    organization: document.body.dataset.organization || "",
    orgDb: document.body.dataset.orgDb || "",
    role: document.body.dataset.role || "",
    organizations: [],
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
    severityBreakdown: {},
    selectedHost: "",
    selectedVulnerabilityId: null,
    selectedScanId: null,
    scanSummary: {
        total: 0,
        active: 0,
        scheduled: 0,
    },
    asmFilters: {
        search: "",
        page: 0,
        limit: 50,
        total: 0,
    },
    asmSummary: {},
    bbotSubdomainFilters: {
        parentDomain: "",
        search: "",
        page: 0,
        limit: 25,
        total: 0,
    },
    scoringFilters: {
        assetSearch: "",
        assetPage: 0,
        assetLimit: 25,
        assetTotal: 0,
        vulnSeverity: "",
        vulnHost: "",
        vulnPage: 0,
        vulnLimit: 25,
        vulnTotal: 0,
    },
    endpointFilters: {
        agentSearch: "",
        agentStatus: "",
        agentPage: 0,
        agentLimit: 25,
        agentTotal: 0,
        softwareSearch: "",
        softwarePage: 0,
        softwareLimit: 50,
        softwareTotal: 0,
        vulnSearch: "",
        vulnSeverity: "",
        vulnPage: 0,
        vulnLimit: 50,
        vulnTotal: 0,
    },
    endpointSeverity: {},
    endpointNetworkMap: {
        nodes: [],
        edges: [],
        summary: {},
        segments: [],
        observations: [],
    },
    endpointNetworkMapHits: [],
    activeScanId: null,
    ws: null,
    wsPingTimer: null,
    debugPollTimer: null,
    debugLogs: [],
    notificationRecipients: [],
    currentUserMfaEnabled: false,
    currentSsoEnabled: false,
    currentSsoSecretConfigured: false,
    scannerAppliances: [],
    mfaPending: false,
    mfaSetupPending: false,
    organizationSelectionPending: false,
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value == null ? "" : String(value);
    return div.innerHTML;
}

function severityClass(value) {
    return (value || "unknown").toString().trim().toLowerCase();
}

function severityBadge(value) {
    const sev = severityClass(value);
    return `<span class="severity-badge ${escapeHtml(sev)}">${escapeHtml(value || "unknown")}</span>`;
}

function hostLink(host) {
    if (!host) return "-";
    return `<button type="button" class="link-button host-link" data-host="${escapeHtml(host)}">${escapeHtml(host)}</button>`;
}

function endpointAgentLink(agentId, label) {
    if (!agentId) return escapeHtml(label || "-");
    return `<button type="button" class="link-button endpoint-agent-link" data-agent-id="${escapeHtml(agentId)}">${escapeHtml(label || agentId)}</button>`;
}

function scoreButton(score, vulnerabilityId) {
    const value = score ?? "-";
    if (!vulnerabilityId) return escapeHtml(value);
    return `<button type="button" class="score-link vulnerability-detail-link" data-vulnerability-id="${escapeHtml(vulnerabilityId)}" title="Bekijk scoreberekening">${escapeHtml(value)}</button>`;
}

function setQrImage(elementId, dataUri) {
    const img = document.getElementById(elementId);
    if (!img) return;
    if (dataUri) {
        img.src = dataUri;
        img.classList.remove("hidden");
    } else {
        img.removeAttribute("src");
        img.classList.add("hidden");
    }
}

function scheduleIntervalMinutes() {
    const amount = Math.max(1, Number(document.getElementById("scheduleIntervalAmountInput").value || 1));
    const unit = document.getElementById("scheduleIntervalUnitInput").value;
    const multipliers = {
        hours: 60,
        days: 1440,
        weeks: 10080,
        months: 43200,
        years: 525600,
    };
    return Math.max(10, Math.min(5256000, Math.round(amount * (multipliers[unit] || 1440))));
}

function dateInputToIso(elementId, endOfDay = false) {
    const value = document.getElementById(elementId)?.value;
    if (!value) return null;
    const normalized = value.includes("T")
        ? value
        : `${value}T${endOfDay ? "23:59:59" : "00:00:00"}`;
    const date = new Date(normalized);
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function scannerApplianceLabel(node) {
    if (!node) return "Auto";
    const name = node.name || node.node_id || "scanner";
    const status = node.status || "unknown";
    const running = `${node.running_jobs ?? 0}/${node.max_parallel_jobs ?? 1}`;
    return `${name} (${status}, ${running} running)`;
}

function scannerApplianceName(nodeId) {
    if (!nodeId) return "Auto";
    const node = state.scannerAppliances.find(item => item.node_id === nodeId);
    return node ? (node.name || node.node_id) : nodeId;
}

async function loadScannerApplianceOptions() {
    const select = document.getElementById("applianceInput");
    if (!select || !state.authenticated || roleRank(state.role) < roleRank("security_analyst")) return;
    const currentValue = select.value;
    try {
        const result = await requestJson("/api/scanner-nodes/available");
        state.scannerAppliances = result.items || [];
        select.innerHTML = [
            '<option value="">Auto - any available appliance</option>',
            ...state.scannerAppliances.map(node => `
                <option value="${escapeHtml(node.node_id)}">${escapeHtml(scannerApplianceLabel(node))}</option>
            `),
        ].join("");
        if (currentValue && state.scannerAppliances.some(node => node.node_id === currentValue)) {
            select.value = currentValue;
        }
    } catch (error) {
        console.warn("Failed to load scanner appliances:", error);
        select.innerHTML = '<option value="">Auto - any available appliance</option>';
    }
}

function formatIntervalMinutes(minutes) {
    const value = Number(minutes || 0);
    const units = [
        ["year", 525600],
        ["month", 43200],
        ["week", 10080],
        ["day", 1440],
        ["hour", 60],
    ];
    for (const [label, unitMinutes] of units) {
        if (value >= unitMinutes && value % unitMinutes === 0) {
            const amount = value / unitMinutes;
            return `Every ${amount} ${label}${amount === 1 ? "" : "s"}`;
        }
    }
    return `Every ${value || 0} minutes`;
}

function updateAttackSurfaceExportLinks() {
    const params = new URLSearchParams();
    if (state.asmFilters.search) params.set("search", state.asmFilters.search);
    const suffix = params.toString() ? `?${params}` : "";
    const csv = document.getElementById("asmCsvExportBtn");
    const xlsx = document.getElementById("asmXlsxExportBtn");
    const html = document.getElementById("asmHtmlExportBtn");
    if (csv) csv.href = `/api/exports/attack-surface.csv${suffix}`;
    if (xlsx) xlsx.href = `/api/exports/attack-surface.xlsx${suffix}`;
    if (html) html.href = `/api/exports/attack-surface.html${suffix}`;
}

function compactList(items, max = 3) {
    const values = (items || []).filter(Boolean);
    if (!values.length) return "-";
    const visible = values.slice(0, max).map(escapeHtml).join(", ");
    return values.length > max ? `${visible} +${values.length - max}` : visible;
}

function formatScanMode(mode) {
    const value = String(mode || "");
    return {
        "1": "Passive",
        "2": "Normal",
        "3": "Aggressive",
        "4": "Attack Surface",
        bbot_passive: "BBot passive",
        bbot_normal: "BBot normal",
        bbot_aggressive: "BBot aggressive",
        bbot_attack_surface: "BBot attack surface",
        rustscan: "RustScan",
        nuclei: "Nuclei standard",
        nucleinetwork: "Nuclei network",
        wordpressnuclei: "Nuclei WordPress",
        openvas: "OpenVAS",
        asteroid_normal: "Asteroid normal",
        asteroid_aggressive: "Asteroid aggressive",
        retirejs: "RetireJS",
        vulnscan: "Vulnscan",
        nikto: "Nikto",
        wapiti: "Wapiti",
        zap: "OWASP ZAP",
        dalfox: "Dalfox",
        testssl: "testssl.sh",
        sslscan: "TLS audit",
    }[value] || value || "-";
}

function formatDateTime(value) {
    if (!value) return "-";
    const normalized = String(value).includes("T") ? value : String(value).replace(" ", "T");
    const date = new Date(normalized);
    if (Number.isNaN(date.getTime())) return value;
    return new Intl.DateTimeFormat(undefined, {
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
    }).format(date);
}

function statusBadge(status) {
    const normalized = severityClass(status);
    return `<span class="status-badge status-${escapeHtml(normalized)}">${escapeHtml(status || "unknown")}</span>`;
}

function updatePager(prefix, page, total, limit) {
    const pageNum = page + 1;
    const totalPages = Math.max(1, Math.ceil((total || 0) / limit));
    const info = document.getElementById(`${prefix}PageInfo`);
    const prev = document.getElementById(`${prefix}PrevBtn`);
    const next = document.getElementById(`${prefix}NextBtn`);
    if (info) info.textContent = `Page ${pageNum} of ${totalPages} (${total || 0} total)`;
    if (prev) prev.disabled = page <= 0;
    if (next) next.disabled = pageNum >= totalPages;
}

const severityPalette = {
    critical: "#f05154",
    high: "#ff7678",
    medium: "#f49e31",
    low: "#5fd0a5",
    baseline: "#83d8ff",
    info: "#83d8ff",
    unknown: "#6f9087",
};

const severityOrder = ["critical", "high", "medium", "low", "baseline", "info", "unknown"];

function severityEntries(breakdown) {
    const normalized = breakdown || {};
    return severityOrder
        .map(severity => [severity, Number(normalized[severity] || normalized[severity.toUpperCase()] || 0)])
        .filter(([, count]) => count > 0);
}

function drawSeverityCanvas(canvasId, breakdown, options = {}) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !canvas.getContext) return;
    const rect = canvas.getBoundingClientRect();
    const cssWidth = Math.max(240, Math.round(rect.width || canvas.width || 360));
    const cssHeight = Math.max(120, Math.round(rect.height || canvas.height || 180));
    const ratio = window.devicePixelRatio || 1;
    canvas.width = Math.round(cssWidth * ratio);
    canvas.height = Math.round(cssHeight * ratio);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    ctx.clearRect(0, 0, cssWidth, cssHeight);

    const entries = severityEntries(breakdown);
    const total = entries.reduce((sum, [, count]) => sum + count, 0);
    const pad = 18;

    ctx.fillStyle = "rgba(95, 208, 165, 0.05)";
    ctx.strokeStyle = "rgba(95, 208, 165, 0.16)";
    ctx.lineWidth = 1;
    for (let i = 0; i < 5; i += 1) {
        const y = pad + ((cssHeight - pad * 2) / 4) * i;
        ctx.beginPath();
        ctx.moveTo(pad, y);
        ctx.lineTo(cssWidth - pad, y);
        ctx.stroke();
    }

    if (!total) {
        ctx.fillStyle = "rgba(238, 252, 247, 0.58)";
        ctx.font = "600 13px Inter, system-ui, sans-serif";
        ctx.fillText("No vulnerability data yet", pad, cssHeight / 2);
        return;
    }

    const donutRadius = Math.min(cssHeight * 0.34, options.compact ? 42 : 62);
    const donutX = pad + donutRadius;
    const donutY = cssHeight / 2;
    let start = -Math.PI / 2;

    entries.forEach(([severity, count]) => {
        const angle = (count / total) * Math.PI * 2;
        ctx.beginPath();
        ctx.arc(donutX, donutY, donutRadius, start, start + angle);
        ctx.strokeStyle = severityPalette[severity] || severityPalette.unknown;
        ctx.lineWidth = options.compact ? 16 : 22;
        ctx.lineCap = "round";
        ctx.stroke();
        start += angle;
    });

    ctx.fillStyle = "#eefcf7";
    ctx.font = options.compact ? "700 24px Inter, system-ui, sans-serif" : "700 32px Inter, system-ui, sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(String(total), donutX, donutY - 4);
    ctx.fillStyle = "rgba(168, 199, 189, 0.9)";
    ctx.font = "600 11px Inter, system-ui, sans-serif";
    ctx.fillText("findings", donutX, donutY + (options.compact ? 18 : 24));

    const barStartX = donutX + donutRadius + 32;
    const barWidth = Math.max(110, cssWidth - barStartX - pad);
    const maxCount = Math.max(...entries.map(([, count]) => count), 1);
    const barGap = options.compact ? 9 : 12;
    const barHeight = Math.max(8, Math.min(18, (cssHeight - pad * 2 - (entries.length - 1) * barGap) / entries.length));
    let y = pad + 4;
    ctx.textAlign = "left";
    ctx.textBaseline = "middle";
    entries.forEach(([severity, count]) => {
        const width = Math.max(6, Math.round((count / maxCount) * barWidth));
        ctx.fillStyle = "rgba(238, 252, 247, 0.52)";
        ctx.font = "600 11px Inter, system-ui, sans-serif";
        ctx.fillText(severity.toUpperCase(), barStartX, y + barHeight / 2);
        const x = barStartX + 86;
        const available = Math.max(24, barWidth - 86);
        ctx.fillStyle = "rgba(95, 208, 165, 0.08)";
        ctx.fillRect(x, y, available, barHeight);
        ctx.fillStyle = severityPalette[severity] || severityPalette.unknown;
        ctx.fillRect(x, y, Math.min(available, width), barHeight);
        ctx.fillStyle = "#eefcf7";
        ctx.font = "700 12px Inter, system-ui, sans-serif";
        const countText = String(count);
        const countWidth = ctx.measureText(countText).width;
        const countX = Math.min(x + Math.min(available, width) + 8, cssWidth - pad - countWidth);
        ctx.fillText(countText, Math.max(x + 4, countX), y + barHeight / 2);
        y += barHeight + barGap;
    });
}

function renderSeverityLegend(targetId, breakdown) {
    const target = document.getElementById(targetId);
    if (!target) return;
    const entries = severityEntries(breakdown);
    target.innerHTML = entries.map(([severity, count]) => `
        <span class="chart-legend-item">
            <i style="background:${severityPalette[severity] || severityPalette.unknown}"></i>
            ${escapeHtml(severity)}
            <strong>${escapeHtml(count)}</strong>
        </span>
    `).join("") || '<span class="muted">No findings yet</span>';
}

function renderVulnerabilityCharts() {
    drawSeverityCanvas("dashboardVulnChart", state.severityBreakdown, { compact: true });
    renderSeverityLegend("dashboardVulnLegend", state.severityBreakdown);
    drawSeverityCanvas("vulnSeverityChart", state.severityBreakdown);
    renderSeverityLegend("vulnSeverityLegend", state.severityBreakdown);
    const total = severityEntries(state.severityBreakdown).reduce((sum, [, count]) => sum + count, 0);
    const totalEl = document.getElementById("vulnChartTotal");
    if (totalEl) totalEl.textContent = `${total} findings`;
}

function renderEndpointCharts(overview = {}) {
    const severity = overview.severity || {};
    drawSeverityCanvas("endpointSeverityChart", severity);
    renderSeverityLegend("endpointSeverityLegend", severity);
    const total = severityEntries(severity).reduce((sum, [, count]) => sum + count, 0);
    const totalEl = document.getElementById("endpointChartTotal");
    if (totalEl) totalEl.textContent = `${total} CVEs`;
}

const networkNodePalette = {
    agent: "#83d8ff",
    network: "#5fd0a5",
    device: "#f49e31",
    endpoint: "#83d8ff",
    server: "#b6a6ff",
    router: "#ffce73",
    firewall: "#f05154",
    phone: "#5fd0a5",
    web_service: "#ffb36b",
    unknown: "#6f9087",
};

function networkNodeColor(node) {
    if (!node) return networkNodePalette.unknown;
    if (node.type === "device") return networkNodePalette[node.device_type] || networkNodePalette.device;
    return networkNodePalette[node.type] || networkNodePalette.unknown;
}

function drawEndpointNetworkMap(map = {}) {
    const canvas = document.getElementById("endpointNetworkMapCanvas");
    if (!canvas || !canvas.getContext) return;
    const nodes = map.nodes || [];
    const edges = map.edges || [];
    const networks = nodes.filter(node => node.type === "network").sort((a, b) => String(a.label || "").localeCompare(String(b.label || "")));
    const agents = nodes.filter(node => node.type === "agent").sort((a, b) => String(a.label || "").localeCompare(String(b.label || "")));
    const devices = nodes.filter(node => node.type === "device").sort((a, b) => String(a.label || "").localeCompare(String(b.label || "")));
    const parentWidth = canvas.parentElement?.clientWidth || canvas.getBoundingClientRect().width || canvas.width || 1100;
    const cssWidth = Math.max(760, Math.round(parentWidth));
    const deviceStartX = Math.round(cssWidth * 0.62);
    const deviceCols = Math.max(2, Math.floor((cssWidth - deviceStartX - 34) / 142));
    const devicesByNetwork = new Map();
    const agentNetworks = new Map();
    const displayNetworks = networks.length ? [...networks] : [{ id: "net:unmapped", type: "network", label: "Unmapped" }];

    displayNetworks.forEach(network => devicesByNetwork.set(network.id, []));
    edges.forEach(edge => {
        if (String(edge.source || "").startsWith("agent:") && String(edge.target || "").startsWith("net:")) {
            const list = agentNetworks.get(edge.source) || [];
            list.push(edge.target);
            agentNetworks.set(edge.source, list);
        }
        if (String(edge.source || "").startsWith("net:") && String(edge.target || "").startsWith("device:")) {
            const list = devicesByNetwork.get(edge.source) || [];
            list.push(edge.target);
            devicesByNetwork.set(edge.source, list);
        }
    });
    const networkIds = new Set(displayNetworks.map(network => network.id));
    const assignedDevices = new Set(Array.from(devicesByNetwork.values()).flat());
    const unassignedDevices = devices.filter(device => !assignedDevices.has(device.id));
    if (unassignedDevices.length) {
        const unmapped = { id: "net:unmapped", type: "network", label: "Unmapped" };
        if (!networkIds.has(unmapped.id)) {
            displayNetworks.push(unmapped);
            networkIds.add(unmapped.id);
        }
        devicesByNetwork.set(unmapped.id, unassignedDevices.map(device => device.id));
    }
    const rowHeights = displayNetworks.map(network => {
        const deviceCount = (devicesByNetwork.get(network.id) || []).length;
        const agentCount = agents.filter(agent => (agentNetworks.get(agent.id) || []).includes(network.id)).length;
        return Math.max(118, Math.ceil(deviceCount / deviceCols) * 42 + 70, agentCount * 38 + 70);
    });
    const cssHeight = Math.max(520, rowHeights.reduce((sum, height) => sum + height, 0) + 116);
    canvas.style.height = `${cssHeight}px`;
    const ratio = window.devicePixelRatio || 1;
    canvas.width = Math.round(cssWidth * ratio);
    canvas.height = Math.round(cssHeight * ratio);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    ctx.clearRect(0, 0, cssWidth, cssHeight);

    ctx.fillStyle = "rgba(5, 13, 16, 0.82)";
    ctx.fillRect(0, 0, cssWidth, cssHeight);
    ctx.strokeStyle = "rgba(95, 208, 165, 0.08)";
    ctx.lineWidth = 1;
    for (let x = 24; x < cssWidth; x += 42) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, cssHeight);
        ctx.stroke();
    }
    for (let y = 24; y < cssHeight; y += 42) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(cssWidth, y);
        ctx.stroke();
    }

    if (!nodes.length) {
        ctx.fillStyle = "rgba(238, 252, 247, 0.58)";
        ctx.font = "700 14px Inter, system-ui, sans-serif";
        ctx.fillText("No endpoint network probes reported yet", 24, cssHeight / 2);
        state.endpointNetworkMapHits = [];
        return;
    }

    const positions = {};
    const agentX = 116;
    const networkX = Math.round(cssWidth * 0.39);
    const rowStartY = 82;
    let currentY = rowStartY;

    ctx.fillStyle = "rgba(168, 199, 189, 0.84)";
    ctx.font = "800 11px Inter, system-ui, sans-serif";
    ctx.textAlign = "left";
    ctx.textBaseline = "middle";
    ctx.fillText("AGENTS", agentX - 72, 36);
    ctx.fillText("NETWORK SEGMENTS", networkX - 94, 36);
    ctx.fillText("OBSERVED DEVICES", deviceStartX - 4, 36);

    displayNetworks.forEach((network, index) => {
        const rowHeight = rowHeights[index];
        const rowY = currentY;
        const centerY = rowY + rowHeight / 2;
        positions[network.id] = { x: networkX, y: centerY, w: 190, h: 50 };
        ctx.fillStyle = index % 2 === 0 ? "rgba(95, 208, 165, 0.035)" : "rgba(131, 216, 255, 0.025)";
        ctx.fillRect(18, rowY, cssWidth - 36, rowHeight - 10);
        ctx.strokeStyle = "rgba(95, 208, 165, 0.10)";
        ctx.strokeRect(18, rowY, cssWidth - 36, rowHeight - 10);
        currentY += rowHeight;
    });

    agents.forEach((agent, index) => {
        const related = (agentNetworks.get(agent.id) || []).filter(networkId => positions[networkId]);
        const baseY = related.length
            ? related.reduce((sum, networkId) => sum + positions[networkId].y, 0) / related.length
            : rowStartY + 44 + index * 56;
        positions[agent.id] = {
            x: agentX + (index % 2) * 36,
            y: Math.max(72, Math.min(cssHeight - 48, baseY + ((index % 3) - 1) * 18)),
            w: 152,
            h: 44,
        };
    });

    displayNetworks.forEach((network, networkIndex) => {
        const ids = devicesByNetwork.get(network.id) || [];
        const rowTop = positions[network.id].y - rowHeights[networkIndex] / 2;
        ids.forEach((deviceId, index) => {
            const node = devices.find(device => device.id === deviceId);
            if (!node) return;
            const col = index % deviceCols;
            const row = Math.floor(index / deviceCols);
            positions[node.id] = {
                x: deviceStartX + col * 142 + 60,
                y: rowTop + 46 + row * 42,
                w: 126,
                h: 32,
            };
        });
    });

    edges.forEach(edge => {
        const source = positions[edge.source];
        const target = positions[edge.target];
        if (!source || !target) return;
        const sourceRight = source.x + (source.w || 0) / 2;
        const sourceLeft = source.x - (source.w || 0) / 2;
        const targetRight = target.x + (target.w || 0) / 2;
        const targetLeft = target.x - (target.w || 0) / 2;
        const startX = source.x < target.x ? sourceRight : sourceLeft;
        const endX = source.x < target.x ? targetLeft : targetRight;
        const curve = Math.max(54, Math.abs(endX - startX) * 0.42);
        ctx.beginPath();
        ctx.moveTo(startX, source.y);
        ctx.bezierCurveTo(startX + curve, source.y, endX - curve, target.y, endX, target.y);
        ctx.strokeStyle = edge.type === "peer_unreachable"
            ? "rgba(240, 81, 84, 0.38)"
            : edge.type === "peer_reachable"
                ? "rgba(131, 216, 255, 0.58)"
                : "rgba(95, 208, 165, 0.24)";
        ctx.lineWidth = edge.type?.startsWith("peer_") ? 2 : 1.4;
        ctx.stroke();
    });

    function roundedRect(x, y, width, height, radius) {
        const r = Math.min(radius, width / 2, height / 2);
        ctx.beginPath();
        ctx.moveTo(x + r, y);
        ctx.arcTo(x + width, y, x + width, y + height, r);
        ctx.arcTo(x + width, y + height, x, y + height, r);
        ctx.arcTo(x, y + height, x, y, r);
        ctx.arcTo(x, y, x + width, y, r);
        ctx.closePath();
    }

    function drawSchematicNode(node, pos) {
        const color = networkNodeColor(node);
        const x = pos.x - pos.w / 2;
        const y = pos.y - pos.h / 2;
        roundedRect(x - 4, y - 4, pos.w + 8, pos.h + 8, 12);
        ctx.fillStyle = `${color}18`;
        ctx.fill();
        roundedRect(x, y, pos.w, pos.h, 9);
        ctx.fillStyle = "rgba(6, 19, 16, 0.92)";
        ctx.fill();
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.4;
        ctx.stroke();
        ctx.fillStyle = color;
        ctx.fillRect(x, y, 4, pos.h);

        const label = String(node.label || node.hostname || node.ip_address || node.id);
        const shortLabel = label.length > 18 ? `${label.slice(0, 15)}...` : label;
        const subtitle = node.type === "agent"
            ? String(node.status || "agent")
            : node.type === "network"
                ? String(node.cidr || "network")
                : String(node.device_type || "device");
        ctx.textAlign = "left";
        ctx.textBaseline = "middle";
        ctx.fillStyle = "#eefcf7";
        ctx.font = node.type === "network" ? "800 12px Inter, system-ui, sans-serif" : "700 11px Inter, system-ui, sans-serif";
        ctx.fillText(shortLabel, x + 12, y + pos.h / 2 - 6);
        ctx.fillStyle = "rgba(168, 199, 189, 0.86)";
        ctx.font = "700 9px Inter, system-ui, sans-serif";
        ctx.fillText(subtitle.length > 20 ? `${subtitle.slice(0, 17)}...` : subtitle, x + 12, y + pos.h / 2 + 9);
    }

    const hits = [];
    nodes.forEach(node => {
        const pos = positions[node.id];
        if (!pos) return;
        drawSchematicNode(node, pos);
        hits.push({ node, x: pos.x - pos.w / 2, y: pos.y - pos.h / 2, w: pos.w, h: pos.h });
    });
    state.endpointNetworkMapHits = hits;
}

function renderEndpointNetworkMap(map = {}) {
    state.endpointNetworkMap = map;
    const summary = map.summary || {};
    const totalEl = document.getElementById("endpointNetworkMapTotal");
    if (totalEl) totalEl.textContent = `${summary.networks || 0} networks`;
    const summaryEl = document.getElementById("endpointNetworkSummary");
    if (summaryEl) {
        summaryEl.innerHTML = [
            ["Agents", summary.agents || 0],
            ["Online", summary.online_agents || 0],
            ["Networks", summary.networks || 0],
            ["Devices", summary.observed_devices || 0],
            ["Firewalls", summary.firewall_candidates || 0],
            ["Peer links", summary.peer_links || 0],
        ].map(([label, value]) => `
            <div class="network-summary-item">
                <span>${escapeHtml(label)}</span>
                <strong>${escapeHtml(value)}</strong>
            </div>
        `).join("");
    }
    const segmentRows = document.getElementById("endpointNetworkSegmentRows");
    if (segmentRows) {
        segmentRows.innerHTML = (map.segments || []).slice(0, 12).map(segment => `
            <tr>
                <td><code>${escapeHtml(segment.cidr || "-")}</code></td>
                <td>${escapeHtml((segment.agents || []).length)}</td>
                <td>${escapeHtml((segment.gateways || []).join(", ") || "-")}</td>
                <td>${escapeHtml(segment.public_ip || "-")}</td>
                <td>${escapeHtml(segment.device_count || 0)}</td>
            </tr>
        `).join("") || '<tr><td colspan="5">No network segments reported yet.</td></tr>';
    }
    const deviceRows = document.getElementById("endpointNetworkDeviceRows");
    if (deviceRows) {
        deviceRows.innerHTML = (map.observations || []).slice(0, 12).map(device => {
            const openPorts = parseMaybeJson(device.open_ports, []);
            return `
                <tr>
                    <td>${escapeHtml(device.hostname || device.ip_address || device.mac_address || "-")}</td>
                    <td>${escapeHtml(device.device_type || "unknown")}</td>
                    <td>${escapeHtml(Array.isArray(openPorts) ? openPorts.join(", ") : "-")}</td>
                    <td>${endpointAgentLink(device.agent_id, device.agent_hostname || device.agent_id)}</td>
                </tr>
            `;
        }).join("") || '<tr><td colspan="4">No devices observed yet.</td></tr>';
    }
    drawEndpointNetworkMap(map);
}

function openEndpointNetworkNodeDetail(node) {
    if (!node) return;
    const fields = [
        detailField("Type", node.type || "-"),
        detailField("Label", node.label || "-"),
    ];
    if (node.type === "agent") {
        fields.push(
            detailField("Status", statusBadge(node.status || "unknown"), { raw: true }),
            detailField("OS", node.os || "-"),
            detailField("IPs", (node.ip_addresses || []).join(", ") || "-"),
            detailField("Endpoint Findings", node.risk || 0),
            detailField("Last Seen", formatDateTime(node.last_seen_at))
        );
    } else if (node.type === "network") {
        fields.push(
            detailField("CIDR", node.cidr || "-"),
            detailField("Public IP", node.public_ip || "-")
        );
    } else {
        fields.push(
            detailField("Device Type", node.device_type || "unknown"),
            detailField("OS Family", node.os_family || "-"),
            detailField("IP", node.ip_address || "-"),
            detailField("MAC", node.mac_address || "-"),
            detailField("Open Ports", (node.open_ports || []).join(", ") || "-"),
            detailField("Confidence", node.confidence ? `${node.confidence}%` : "-"),
            detailField("Seen By", endpointAgentLink(node.agent_id, node.agent_id), { raw: true }),
            detailField("Last Seen", formatDateTime(node.last_seen_at))
        );
    }
    openDetailDrawer("Network Map", node.label || node.id, `<div class="detail-grid">${fields.join("")}</div>`);
}

function drawScanActivityCanvas() {
    const canvas = document.getElementById("dashboardScanChart");
    if (!canvas || !canvas.getContext) return;
    const rect = canvas.getBoundingClientRect();
    const cssWidth = Math.max(240, Math.round(rect.width || canvas.width || 320));
    const cssHeight = Math.max(120, Math.round(rect.height || canvas.height || 140));
    const ratio = window.devicePixelRatio || 1;
    canvas.width = Math.round(cssWidth * ratio);
    canvas.height = Math.round(cssHeight * ratio);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    ctx.clearRect(0, 0, cssWidth, cssHeight);

    const values = [
        { label: "Scans", value: Number(state.scanSummary.total || 0), color: "#83d8ff" },
        { label: "Active", value: Number(state.scanSummary.active || 0), color: "#5fd0a5" },
        { label: "Scheduled", value: Number(state.scanSummary.scheduled || 0), color: "#f49e31" },
    ];
    const max = Math.max(...values.map(item => item.value), 1);
    const pad = 18;
    const barGap = 16;
    const barHeight = 22;
    const labelWidth = 76;
    const barWidth = cssWidth - pad * 2 - labelWidth - 34;
    let y = pad + 6;

    ctx.strokeStyle = "rgba(95, 208, 165, 0.14)";
    ctx.lineWidth = 1;
    for (let i = 0; i < 4; i += 1) {
        const x = pad + labelWidth + (barWidth / 3) * i;
        ctx.beginPath();
        ctx.moveTo(x, pad);
        ctx.lineTo(x, cssHeight - pad);
        ctx.stroke();
    }

    values.forEach(item => {
        const width = Math.max(5, (item.value / max) * barWidth);
        ctx.fillStyle = "rgba(238, 252, 247, 0.64)";
        ctx.font = "700 11px Inter, system-ui, sans-serif";
        ctx.textAlign = "left";
        ctx.textBaseline = "middle";
        ctx.fillText(item.label.toUpperCase(), pad, y + barHeight / 2);
        const x = pad + labelWidth;
        ctx.fillStyle = "rgba(95, 208, 165, 0.08)";
        ctx.fillRect(x, y, barWidth, barHeight);
        ctx.fillStyle = item.color;
        ctx.fillRect(x, y, width, barHeight);
        ctx.fillStyle = "#eefcf7";
        ctx.font = "800 13px Inter, system-ui, sans-serif";
        ctx.fillText(String(item.value), x + Math.min(width + 8, barWidth + 8), y + barHeight / 2);
        y += barHeight + barGap;
    });
}

function drawAttackSurfaceCanvas(summary = {}) {
    const canvas = document.getElementById("asmExposureChart");
    const legend = document.getElementById("asmExposureLegend");
    if (!canvas || !canvas.getContext) return;
    const values = [
        { label: "Assets", value: Number(summary.asset_count || 0), color: "#83d8ff" },
        { label: "Open Ports", value: Number(summary.exposed_ports || 0), color: "#f49e31" },
        { label: "Services", value: Number(summary.service_count || 0), color: "#5fd0a5" },
        { label: "Exploitable", value: Number(summary.exploitable_assets || 0), color: "#ff7678" },
        { label: "Critical", value: Number(summary.critical_assets || 0), color: "#f05154" },
    ];
    const rect = canvas.getBoundingClientRect();
    const cssWidth = Math.max(300, Math.round(rect.width || canvas.width || 520));
    const cssHeight = Math.max(140, Math.round(rect.height || canvas.height || 160));
    const ratio = window.devicePixelRatio || 1;
    canvas.width = Math.round(cssWidth * ratio);
    canvas.height = Math.round(cssHeight * ratio);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    ctx.clearRect(0, 0, cssWidth, cssHeight);

    const pad = 18;
    const max = Math.max(...values.map(item => item.value), 1);
    const barWidth = (cssWidth - pad * 2) / values.length;
    values.forEach((item, index) => {
        const height = Math.max(6, ((cssHeight - 58) * item.value) / max);
        const x = pad + index * barWidth + 8;
        const y = cssHeight - pad - height;
        ctx.fillStyle = "rgba(95, 208, 165, 0.08)";
        ctx.fillRect(x, pad, Math.max(18, barWidth - 16), cssHeight - pad * 2);
        ctx.fillStyle = item.color;
        ctx.fillRect(x, y, Math.max(18, barWidth - 16), height);
        ctx.fillStyle = "#eefcf7";
        ctx.font = "800 13px Inter, system-ui, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText(String(item.value), x + (barWidth - 16) / 2, y - 8);
        ctx.fillStyle = "rgba(168, 199, 189, 0.92)";
        ctx.font = "700 10px Inter, system-ui, sans-serif";
        ctx.fillText(item.label.toUpperCase(), x + (barWidth - 16) / 2, cssHeight - 5);
    });
    if (legend) {
        legend.innerHTML = values.map(item => `
            <span class="chart-legend-item">
                <i style="background:${item.color}"></i>
                ${escapeHtml(item.label)}
                <strong>${escapeHtml(item.value)}</strong>
            </span>
        `).join("");
    }
}

function updateVulnerabilityReportLink() {
    const link = document.getElementById("htmlReportExportBtn");
    const xlsxLink = document.getElementById("xlsxExportBtn");
    const params = new URLSearchParams();
    if (state.vulnFilters.severity) params.set("severity", state.vulnFilters.severity);
    if (state.vulnFilters.host) params.set("host", state.vulnFilters.host);
    if (state.vulnFilters.tool) params.set("tool", state.vulnFilters.tool);
    const suffix = params.toString() ? `?${params}` : "";
    if (link) link.href = `/api/exports/vulnerabilities.html${suffix}`;
    if (xlsxLink) xlsxLink.href = `/api/exports/vulnerabilities.xlsx${suffix}`;
}

function detailField(label, value, options = {}) {
    const content = value == null || value === "" ? "-" : value;
    const rendered = options.raw ? content : escapeHtml(content);
    return `
        <div class="detail-field">
            <span>${escapeHtml(label)}</span>
            <strong>${rendered}</strong>
        </div>
    `;
}

function detailSection(title, value) {
    if (value == null || value === "") return "";
    return `
        <section class="detail-section">
            <h4>${escapeHtml(title)}</h4>
            <p>${escapeHtml(value)}</p>
        </section>
    `;
}

function scoreDetailSection(score, reason) {
    if ((score == null || score === "") && !reason) return "";
    return `
        <section class="detail-section score-calculation">
            <div class="detail-section-header">
                <h4>Score Calculation</h4>
                <span class="score-pill">${escapeHtml(score ?? "-")}</span>
            </div>
            <p>${escapeHtml(reason || "Geen scoreberekening opgeslagen. Gebruik Recalculate Scores om de prioriteit opnieuw te laten berekenen.")}</p>
        </section>
    `;
}

function detailPre(title, value) {
    if (value == null || value === "") return "";
    return `
        <section class="detail-section">
            <h4>${escapeHtml(title)}</h4>
            <pre>${escapeHtml(value)}</pre>
        </section>
    `;
}

function parseMaybeJson(value, fallback = null) {
    if (value == null || value === "") return fallback;
    if (typeof value === "object") return value;
    try {
        return JSON.parse(value);
    } catch {
        return fallback;
    }
}

function compactList(value) {
    const parsed = parseMaybeJson(value, Array.isArray(value) ? value : []);
    if (Array.isArray(parsed)) return parsed.filter(Boolean).join(", ") || "-";
    return String(value || "-");
}

function openDetailDrawer(eyebrow, title, bodyHtml) {
    const overlay = document.getElementById("detailOverlay");
    document.getElementById("detailEyebrow").textContent = eyebrow;
    document.getElementById("detailTitle").textContent = title;
    document.getElementById("detailBody").innerHTML = bodyHtml;
    overlay.classList.remove("hidden");
    overlay.setAttribute("aria-hidden", "false");
}

function closeDetailDrawer() {
    const overlay = document.getElementById("detailOverlay");
    if (!overlay) return;
    overlay.classList.add("hidden");
    overlay.setAttribute("aria-hidden", "true");
    document.getElementById("detailBody").innerHTML = "";
}

async function openVulnerabilityDetail(vulnerabilityId) {
    if (!vulnerabilityId) return;
    state.selectedVulnerabilityId = vulnerabilityId;
    openDetailDrawer("Vulnerability", `Finding ${vulnerabilityId}`, '<div class="empty-state">Loading vulnerability details...</div>');
    try {
        const vuln = await requestJson(`/api/vulnerabilities/${encodeURIComponent(vulnerabilityId)}`);
        const exploit = vuln.has_public_exploit || vuln.has_poc ? "Yes" : "No";
        const score = vuln.priority_score ?? vuln.risk_score ?? "-";
        openDetailDrawer("Vulnerability", vuln.title || vuln.cve || `Finding ${vuln.id}`, `
            <div class="detail-metrics">
                ${detailField("Severity", severityBadge(vuln.severity), { raw: true })}
                ${detailField("Priority", score)}
                ${detailField("Exploit", exploit)}
                ${detailField("Confidence", vuln.confidence != null ? `${vuln.confidence}%` : "-")}
            </div>
            <div class="detail-grid">
                ${detailField("Host", hostLink(vuln.host), { raw: true })}
                ${detailField("Tool", vuln.tool || "-")}
                ${detailField("CVE", vuln.cve || "-")}
                ${detailField("Affected Item", vuln.affected_item || "-")}
                ${detailField("CVSS", vuln.cvss || "-")}
                ${detailField("EPSS", vuln.epss || "-")}
                ${detailField("KEV", vuln.kev ? "Yes" : "No")}
                ${detailField("Exploit Maturity", vuln.exploit_maturity || "-")}
            </div>
            ${detailSection("Summary", vuln.summary)}
            ${detailSection("Impact", vuln.impact)}
            ${detailSection("Recommended Fix", vuln.solution)}
            ${scoreDetailSection(score, vuln.score_reason)}
            ${detailPre("References", vuln.references)}
            ${detailPre("Proofs / PoCs", vuln.pocs)}
        `);
    } catch (error) {
        openDetailDrawer("Vulnerability", `Finding ${vulnerabilityId}`, `<div class="empty-state">Failed to load details: ${escapeHtml(error.message)}</div>`);
    }
}

function scanDuration(scan) {
    const startValue = scan.started_at || scan.created_at;
    const endValue = scan.finished_at || scan.stopped_at || scan.requested_stop_at;
    if (!startValue || !endValue) return "-";
    const start = new Date(String(startValue).includes("T") ? startValue : String(startValue).replace(" ", "T"));
    const end = new Date(String(endValue).includes("T") ? endValue : String(endValue).replace(" ", "T"));
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return "-";
    const seconds = Math.max(0, Math.round((end - start) / 1000));
    const minutes = Math.floor(seconds / 60);
    const remainder = seconds % 60;
    return minutes ? `${minutes}m ${remainder}s` : `${remainder}s`;
}

async function openScanDetail(scanId) {
    if (!scanId) return;
    state.selectedScanId = scanId;
    openDetailDrawer("Scan", `Scan ${scanId}`, '<div class="empty-state">Loading scan details...</div>');
    try {
        const result = await requestJson(`/api/scans/${encodeURIComponent(scanId)}`);
        const scan = result.scan || {};
        const logs = result.logs || [];
        const logPreview = logs.slice(-80).map(log => {
            const time = formatDateTime(log.created_at);
            return `[${time}] ${String(log.log_level || "info").toUpperCase()} ${log.message || ""}`;
        }).join("\n");
        openDetailDrawer("Scan", `${scan.scan_name || "Scan"} #${scan.id}`, `
            <div class="detail-metrics">
                ${detailField("Mode", formatScanMode(scan.scan_mode))}
                ${detailField("Status", statusBadge(scan.status), { raw: true })}
                ${detailField("Duration", scanDuration(scan))}
                ${detailField("Schedule", scan.schedule_id || "-")}
            </div>
            <div class="detail-grid">
                ${detailField("Targets", scan.targets || "-")}
                ${detailField("Created", formatDateTime(scan.created_at))}
                ${detailField("Started", formatDateTime(scan.started_at))}
                ${detailField("Finished", formatDateTime(scan.finished_at || scan.stopped_at))}
                ${detailField("Stop Requested", formatDateTime(scan.requested_stop_at))}
                ${detailField("Error", scan.error_message || "-")}
            </div>
            <section class="detail-section">
                <div class="detail-section-header">
                    <h4>Execution Log</h4>
                    <button type="button" class="btn-secondary btn-sm open-debug-scan-btn" data-scan-id="${escapeHtml(scan.id)}">Open Debug</button>
                </div>
                <pre>${escapeHtml(logPreview || "No logs recorded yet.")}</pre>
            </section>
        `);
    } catch (error) {
        openDetailDrawer("Scan", `Scan ${scanId}`, `<div class="empty-state">Failed to load scan details: ${escapeHtml(error.message)}</div>`);
    }
}

async function openEndpointAgentDetail(agentId) {
    if (!agentId) return;
    openDetailDrawer("Endpoint", agentId, '<div class="empty-state">Loading endpoint details...</div>');
    try {
        const [agent, software, vulns] = await Promise.all([
            requestJson(`/api/endpoints/agents/${encodeURIComponent(agentId)}`),
            requestJson(`/api/endpoints/software?agent_id=${encodeURIComponent(agentId)}&limit=12`),
            requestJson(`/api/endpoints/vulnerabilities?agent_id=${encodeURIComponent(agentId)}&limit=12`),
        ]);
        const softwareRows = (software.items || []).map(item => `
            <tr>
                <td>${escapeHtml(item.name || "-")}</td>
                <td>${escapeHtml(item.version || "-")}</td>
                <td>${escapeHtml(item.ecosystem || "-")}</td>
            </tr>
        `).join("") || '<tr><td colspan="3">No software inventory yet.</td></tr>';
        const vulnRows = (vulns.items || []).map(vuln => `
            <tr class="severity-row ${escapeHtml(severityClass(vuln.severity))}">
                <td>${severityBadge(vuln.severity || "info")}</td>
                <td><button type="button" class="link-button endpoint-vuln-link" data-endpoint-vuln-id="${escapeHtml(vuln.id)}">${escapeHtml(vuln.cve || "-")}</button></td>
                <td>${escapeHtml(vuln.software_name || "-")}</td>
            </tr>
        `).join("") || '<tr><td colspan="3">No endpoint findings matched.</td></tr>';
        const metadata = parseMaybeJson(agent.metadata_json, {});
        openDetailDrawer("Endpoint", agent.hostname || agent.agent_id, `
            <div class="detail-metrics">
                ${detailField("Status", statusBadge(agent.status || "unknown"), { raw: true })}
                ${detailField("Agent", agent.agent_id)}
                ${detailField("Last Seen", formatDateTime(agent.last_seen_at))}
                ${detailField("Inventory", formatDateTime(agent.last_inventory_at))}
            </div>
            <div class="detail-grid">
                ${detailField("OS", [agent.os_name, agent.os_version, agent.os_arch].filter(Boolean).join(" ") || "-")}
                ${detailField("Agent Version", agent.agent_version || "-")}
                ${detailField("IP Addresses", compactList(agent.ip_addresses))}
                ${detailField("MAC Addresses", compactList(agent.mac_addresses))}
                ${detailField("Enrolled", formatDateTime(agent.first_seen_at))}
                ${detailField("Revoked", formatDateTime(agent.revoked_at))}
            </div>
            <section class="detail-section">
                <h4>Recent Software</h4>
                <div class="table-container">
                    <table class="data-table no-sort"><thead><tr><th>Name</th><th>Version</th><th>Ecosystem</th></tr></thead><tbody>${softwareRows}</tbody></table>
                </div>
            </section>
            <section class="detail-section">
                <h4>Endpoint Vulnerabilities</h4>
                <div class="table-container">
                    <table class="data-table no-sort"><thead><tr><th>Severity</th><th>CVE</th><th>Software</th></tr></thead><tbody>${vulnRows}</tbody></table>
                </div>
            </section>
            ${detailPre("Metadata", Object.keys(metadata || {}).length ? JSON.stringify(metadata, null, 2) : "")}
        `);
    } catch (error) {
        openDetailDrawer("Endpoint", agentId, `<div class="empty-state">Failed to load endpoint details: ${escapeHtml(error.message)}</div>`);
    }
}

async function openEndpointVulnerabilityDetail(findingId) {
    if (!findingId) return;
    openDetailDrawer("Endpoint Finding", `Finding ${findingId}`, '<div class="empty-state">Loading endpoint vulnerability...</div>');
    try {
        const vuln = await requestJson(`/api/endpoints/vulnerabilities/${encodeURIComponent(findingId)}`);
        const evidence = parseMaybeJson(vuln.evidence_json, {});
        openDetailDrawer("Endpoint Finding", vuln.cve || `Finding ${findingId}`, `
            <div class="detail-metrics">
                ${detailField("Severity", severityBadge(vuln.severity || "info"), { raw: true })}
                ${detailField("CVSS", vuln.cvss || "-")}
                ${detailField("Confidence", vuln.confidence != null ? `${vuln.confidence}%` : "-")}
                ${detailField("Source", vuln.source || "-")}
            </div>
            <div class="detail-grid">
                ${detailField("Endpoint", endpointAgentLink(vuln.agent_id, vuln.hostname || vuln.agent_id), { raw: true })}
                ${detailField("OS", [vuln.os_name, vuln.os_version, vuln.os_arch].filter(Boolean).join(" ") || "-")}
                ${detailField("Software", vuln.software_name || "-")}
                ${detailField("Installed Version", vuln.software_version || vuln.affected_version || "-")}
                ${detailField("Fixed Version", vuln.fixed_version || "-")}
                ${detailField("PURL", vuln.purl || vuln.software_purl || "-")}
            </div>
            ${detailSection("Summary", vuln.summary)}
            ${detailPre("Matcher Evidence", Object.keys(evidence || {}).length ? JSON.stringify(evidence, null, 2) : "")}
        `);
    } catch (error) {
        openDetailDrawer("Endpoint Finding", `Finding ${findingId}`, `<div class="empty-state">Failed to load endpoint vulnerability: ${escapeHtml(error.message)}</div>`);
    }
}

async function requestJson(url, options = {}) {
    const response = await fetch(url, {
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        ...options,
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(formatApiError(payload.detail || payload.error || "Request failed"));
    }
    return payload;
}

function formatApiError(detail) {
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
        return detail.map(item => {
            if (typeof item === "string") return item;
            const location = Array.isArray(item.loc) ? item.loc.filter(part => part !== "body").join(".") : "";
            const msg = item.msg || item.message || JSON.stringify(item);
            return location ? `${location}: ${msg}` : msg;
        }).join("; ");
    }
    if (detail && typeof detail === "object") {
        return detail.message || detail.msg || JSON.stringify(detail);
    }
    return "Request failed";
}

function passwordPolicyError(password) {
    if (!password) return "";
    if (password.length < 8) return "Password must be at least 8 characters.";
    const missing = [];
    if (!/[a-z]/.test(password)) missing.push("one lowercase letter");
    if (!/[A-Z]/.test(password)) missing.push("one uppercase letter");
    if (!/\d/.test(password)) missing.push("one number");
    if (!/[^A-Za-z0-9]/.test(password)) missing.push("one special character");
    return missing.length ? `Password must include ${missing.join(", ")}.` : "";
}

function closeAuthSetupPanels(exceptPanelId = "") {
    if (exceptPanelId !== "mfaSetupPanel") {
        document.getElementById("mfaSetupPanel")?.classList.add("hidden");
        setQrImage("mfaQrImage", null);
    }
    if (exceptPanelId !== "ssoSetupPanel") {
        document.getElementById("ssoSetupPanel")?.classList.add("hidden");
    }
}

function setAuthUI() {
    const loginPanel = document.getElementById("loginScreen");
    const dashboardPanel = document.getElementById("mainDashboard");
    const logoutBtn = document.getElementById("logoutBtn");
    
    if (loginPanel) loginPanel.classList.toggle("hidden", state.authenticated);
    if (dashboardPanel) dashboardPanel.classList.toggle("hidden", !state.authenticated);
    if (logoutBtn) logoutBtn.classList.toggle("hidden", !state.authenticated);
}

function roleRank(role) {
    return {
        viewer: 10,
        security_analyst: 50,
        tenant_admin: 80,
        platform_admin: 100,
    }[role || "viewer"] || 0;
}

function applyRoleUI() {
    const isPlatformAdmin = state.role === "platform_admin";
    const isTenantAdmin = roleRank(state.role) >= roleRank("tenant_admin");
    const canWrite = roleRank(state.role) >= roleRank("security_analyst");
    document.querySelectorAll(".admin-only").forEach(el => {
        el.classList.toggle("hidden", !isPlatformAdmin);
    });
    document.querySelectorAll(".tenant-admin-only").forEach(el => {
        el.classList.toggle("hidden", !isTenantAdmin);
    });
    document.querySelectorAll(".write-action").forEach(el => {
        el.disabled = !canWrite;
        el.classList.toggle("hidden", !canWrite);
    });
}

function renderTenantSwitch(me = {}) {
    const group = document.getElementById("tenantSwitchGroup");
    const select = document.getElementById("tenantSwitchSelect");
    if (!group || !select) return;
    const memberships = me.organizations || state.organizations || [];
    state.organizations = memberships;
    if (!memberships.length) {
        group.classList.add("hidden");
        select.innerHTML = "";
        return;
    }
    select.innerHTML = memberships.map(org => {
        const orgDb = org.org_db_name || org.org_db;
        return `<option value="${escapeHtml(orgDb)}">${escapeHtml(org.org_name || orgDb)}</option>`;
    }).join("");
    select.value = me.org_db || state.orgDb || "";
    group.classList.toggle("hidden", memberships.length < 2);
}

async function completeAuth(result, messageText = "Ingelogd.") {
    state.authenticated = true;
    state.organization = result.organization;
    state.orgDb = result.org_db;
    state.role = result.role || "viewer";
    state.mfaPending = false;
    state.mfaSetupPending = false;
    state.organizationSelectionPending = false;
    if (result.organizations) {
        state.organizations = result.organizations;
    }
    document.getElementById("mfaLoginGroup").classList.add("hidden");
    document.getElementById("mfaSetupLoginPanel").classList.add("hidden");
    setQrImage("mfaLoginQrImage", null);
    document.getElementById("orgChoiceGroup").classList.add("hidden");
    document.getElementById("mfaCodeInput").required = false;
    setAuthUI();
    applyRoleUI();
    const loginMessage = document.getElementById("loginMessage");
    if (loginMessage) loginMessage.textContent = messageText;
    await refreshDashboard();
    await loadFilterOptions();
}

function handleAuthStep(result) {
    const loginMessage = document.getElementById("loginMessage");
    if (result.organization_required) {
        state.organizationSelectionPending = true;
        const select = document.getElementById("orgChoiceInput");
        select.innerHTML = (result.organizations || []).map(org => `
            <option value="${escapeHtml(org.org_db)}">${escapeHtml(org.org_name)} (${escapeHtml(org.role)})</option>
        `).join("");
        document.getElementById("orgChoiceGroup").classList.remove("hidden");
        loginMessage.textContent = "Kies de organisatie waarmee je wilt werken.";
        return true;
    }
    if (result.mfa_required) {
        state.mfaPending = true;
        document.getElementById("mfaLoginGroup").classList.remove("hidden");
        document.getElementById("mfaCodeInput").required = true;
        loginMessage.textContent = "MFA is verplicht. Vul je authenticator-code in.";
        return true;
    }
    if (result.mfa_setup_required) {
        state.mfaSetupPending = true;
        document.getElementById("mfaSetupLoginPanel").classList.remove("hidden");
        document.getElementById("mfaLoginGroup").classList.remove("hidden");
        document.getElementById("mfaCodeInput").required = true;
        document.getElementById("mfaLoginSecretOutput").textContent = result.secret;
        document.getElementById("mfaLoginOtpAuthOutput").value = result.otpauth_url;
        setQrImage("mfaLoginQrImage", result.qr_data_uri);
        loginMessage.textContent = "MFA is verplicht. Stel MFA in en bevestig met een code.";
        return true;
    }
    return false;
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

    if (tabName === "vulns") {
        renderVulnerabilityCharts();
        return loadFilteredVulnerabilities();
    }
    if (tabName === "targets")  return loadTargetsView();
    if (tabName === "surface")  return Promise.all([loadAttackSurfaceView(), loadBbotSubdomainsView()]);
    if (tabName === "endpoints") return loadEndpointsView();
    if (tabName === "scoring")  return loadScoringView();
    if (tabName === "debug")    return loadDebugPanel();
    if (tabName === "host")     return loadHostView();
    if (tabName === "scan") return Promise.all([refreshDashboard(), loadScannerApplianceOptions(), loadSchedulesView()]);
    if (tabName === "schedules") return loadSchedulesView();
    if (tabName === "settings") return Promise.all([loadNotificationSettings(), loadSecurityView()]);
    if (tabName === "m365") return loadM365View();
    if (tabName === "docs") {
        ensureDocsPage();
        return Promise.resolve();
    }
    if (tabName === "oversight") return loadOversightView();
    return Promise.resolve();
}

function switchDocsPage(pageName = "overview") {
    const requestedPage = pageName || "overview";
    const targetPanel = document.querySelector(`[data-docs-page-panel="${requestedPage}"]`);
    const nextPage = targetPanel ? requestedPage : "overview";

    document.querySelectorAll("[data-docs-page-panel]").forEach(panel => {
        panel.classList.toggle("active", panel.dataset.docsPagePanel === nextPage);
    });
    document.querySelectorAll(".docs-nav-button").forEach(button => {
        button.classList.toggle("active", button.dataset.docsPage === nextPage);
    });
}

function ensureDocsPage() {
    const activePage = document.querySelector("[data-docs-page-panel].active");
    switchDocsPage(activePage?.dataset.docsPagePanel || "overview");
}

// ============================================================================
// DASHBOARD TAB
// ============================================================================

function renderSeverityList(breakdown) {
    state.severityBreakdown = breakdown || {};
    renderVulnerabilityCharts();
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
                ${escapeHtml(formatScanMode(scan.scan_mode))} &middot;
                ${statusBadge(scan.status)}
            </div>
            <button class="btn-danger btn-sm stop-scan-btn" data-scan-id="${scan.id}">Stop</button>
        </div>
    `).join("");
}

function renderScans(items) {
    const target = document.getElementById("scanRows");
    if (!items.length) {
        target.innerHTML = '<tr><td colspan="6">No scans started yet.</td></tr>';
        return;
    }

    target.innerHTML = items
        .map((scan) => {
            const status = (scan.status || "unknown").toLowerCase();
            return `
                <tr class="clickable-row scan-detail-row" data-scan-id="${escapeHtml(scan.id)}">
                    <td>${scan.id}</td>
                    <td>${escapeHtml(scan.scan_name || "-")}</td>
                    <td>${escapeHtml(formatScanMode(scan.scan_mode))}</td>
                    <td>${statusBadge(scan.status)}</td>
                    <td><span class="date-text">${escapeHtml(formatDateTime(scan.created_at))}</span></td>
                    <td>${status === "running" || status === "queued" || status === "stopping" ? `<button class="btn-danger btn-sm stop-scan-btn" data-scan-id="${scan.id}">Stop</button>` : "-"}</td>
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
            state.role = me.role || "";
            renderTenantSwitch(me);
            const topRoleName = document.getElementById("topRoleName");
            if (topRoleName) {
                topRoleName.textContent = state.role || "viewer";
            }
            applyRoleUI();
        }

        document.getElementById("statTotal").textContent = stats.total_vulnerabilities ?? 0;
        document.getElementById("statRunning").textContent = stats.running_scans ?? 0;
        document.getElementById("statScanTotal").textContent = stats.total_scans ?? (scans.items || []).length;
        document.getElementById("statScheduled").textContent = stats.scheduled_scans ?? 0;
        state.scanSummary = {
            total: stats.total_scans ?? (scans.items || []).length,
            active: stats.running_scans ?? 0,
            scheduled: stats.scheduled_scans ?? 0,
        };
        drawScanActivityCanvas();
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
        hostSelect.innerHTML = '<option value="">All Hosts</option>';
        hostsRes.items.forEach(host => {
            const opt = document.createElement("option");
            opt.value = host;
            opt.textContent = host;
            hostSelect.appendChild(opt);
        });

        // Populate tool filter
        const toolSelect = document.getElementById("filterTool");
        toolSelect.innerHTML = '<option value="">All Tools</option>';
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
        updateVulnerabilityReportLink();
        renderVulnerabilityCharts();
        if (state.vulnFilters.groupBy === "asset" || state.vulnFilters.groupBy === "vulnerability") {
            const grouped = await requestJson(`/api/vulnerabilities/grouped?group_by=${state.vulnFilters.groupBy}`);
            renderServerGroupedVulnerabilities(grouped.items || []);
            document.getElementById("pageInfo").textContent = `${grouped.items.length} groups`;
            document.getElementById("resultCount").textContent = `${grouped.items.length} groups`;
            document.getElementById("prevPageBtn").disabled = true;
            document.getElementById("nextPageBtn").disabled = true;
            return;
        }

        const params = new URLSearchParams({
            limit: state.vulnFilters.limit,
            offset: state.vulnFilters.page * state.vulnFilters.limit,
            dedupe: state.vulnFilters.groupBy === "none" ? "true" : "false",
        });

        if (state.vulnFilters.severity) params.append("severity", state.vulnFilters.severity);
        if (state.vulnFilters.host) params.append("host", state.vulnFilters.host);
        if (state.vulnFilters.tool) params.append("tool", state.vulnFilters.tool);

        const result = await requestJson(`/api/vulnerabilities/filtered?${params}`);
        state.vulnTotal = result.total;

        let items = result.items || [];

        // Group if needed
        if (state.vulnFilters.groupBy !== "none" && state.vulnFilters.groupBy !== "raw") {
            items = groupVulnerabilities(items, state.vulnFilters.groupBy);
        }

        renderFilteredVulnerabilities(items);
        updatePaginationInfo();
    } catch (error) {
        console.error("Failed to load filtered vulnerabilities:", error);
        document.getElementById("vulnRows").innerHTML = 
            '<tr><td colspan="8">Error loading vulnerabilities.</td></tr>';
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

function renderServerGroupedVulnerabilities(items) {
    const target = document.getElementById("vulnRows");
    if (!items.length) {
        target.innerHTML = '<tr><td colspan="8">No grouped vulnerabilities found.</td></tr>';
        return;
    }
    target.innerHTML = items.map(group => `
        <tr>
            <td colspan="3"><strong>${escapeHtml(group.group_key || "-")}</strong></td>
            <td>${escapeHtml(group.count || 0)} findings</td>
            <td colspan="2">Max score: ${escapeHtml(group.max_priority || 0)}</td>
            <td colspan="2">${escapeHtml(group.hosts || group.vulnerabilities || "-")}</td>
        </tr>
    `).join("");
}

function renderFilteredVulnerabilities(items) {
    const target = document.getElementById("vulnRows");

    if (state.vulnFilters.groupBy !== "none" && state.vulnFilters.groupBy !== "raw") {
        // Render grouped
        target.innerHTML = items.map(group => {
            const rows = group.items.map(item => {
                const sev = (item.severity || "unknown").toLowerCase();
                return `
                    <tr class="vuln-row-${escapeHtml(sev)} clickable-row vulnerability-detail-row" data-vulnerability-id="${escapeHtml(item.id)}">
                        <td>${item.id}</td>
                        <td>${scoreButton(item.priority_score, item.id)}</td>
                        <td>${severityBadge(item.severity)}</td>
                        <td><button type="button" class="link-button detail-link vulnerability-detail-link" data-vulnerability-id="${escapeHtml(item.id)}">${escapeHtml(item.title || "-")}</button></td>
                        <td>${hostLink(item.host)}</td>
                        <td>${escapeHtml(item.tool || "-")}</td>
                        <td>${escapeHtml(item.cve || "-")}</td>
                        <td>${item.has_public_exploit ? "Yes" : "No"}</td>
                    </tr>
                `;
            }).join("");

            return `
                <tr style="background: rgba(109, 224, 255, 0.1);">
                    <td colspan="8" style="font-weight: 700; padding: 8px;">${group.group}</td>
                </tr>
                ${rows}
            `;
        }).join("");
    } else {
        // Render flat
        if (!items.length) {
            target.innerHTML = '<tr><td colspan="8">No vulnerabilities match filters.</td></tr>';
            return;
        }

        target.innerHTML = items.map(item => {
            const sev = (item.severity || "unknown").toLowerCase();
            const duplicateText = item.duplicate_count && Number(item.duplicate_count) > 1
                ? ` <span class="dedupe-count">x${item.duplicate_count}</span>`
                : "";
            return `
                <tr class="vuln-row-${escapeHtml(sev)} clickable-row vulnerability-detail-row" data-vulnerability-id="${escapeHtml(item.id)}">
                    <td>${item.id}</td>
                    <td>${scoreButton(item.priority_score, item.id)}</td>
                    <td>${severityBadge(item.severity)}</td>
                    <td><button type="button" class="link-button detail-link vulnerability-detail-link" data-vulnerability-id="${escapeHtml(item.id)}">${escapeHtml(item.title || "-")}</button>${duplicateText}</td>
                    <td>${hostLink(item.host)}</td>
                    <td>${escapeHtml(item.tool || "-")}</td>
                    <td>${escapeHtml(item.cve || "-")}</td>
                    <td>${item.has_public_exploit ? "Yes" : "No"}</td>
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
                    <td>${hostLink(host.host)}</td>
                    <td>${host.count}</td>
                    <td>${severityBadge(host.maxSeverity)}</td>
                </tr>
            `).join("");

        document.getElementById("targetsRows").innerHTML = rows || 
            '<tr><td colspan="3">No targets discovered yet.</td></tr>';
    } catch (error) {
        console.error("Failed to load targets:", error);
    }
}

async function openHostView(host) {
    state.selectedHost = host;
    const hostButton = document.getElementById("hostTabButton");
    if (hostButton) {
        hostButton.textContent = host;
        hostButton.classList.remove("hidden");
    }
    await switchTab("host");
}

async function loadHostView() {
    const host = state.selectedHost;
    if (!host) return;
    document.getElementById("hostDetailTitle").textContent = host;
    try {
        const params = new URLSearchParams({
            host,
            limit: 200,
            offset: 0,
            dedupe: "true",
        });
        const result = await requestJson(`/api/vulnerabilities/filtered?${params}`);
        const items = result.items || [];
        const severities = {};
        items.forEach(item => {
            const sev = severityClass(item.severity);
            severities[sev] = (severities[sev] || 0) + 1;
        });
        const maxSeverity = Object.keys(severities).sort((a, b) => {
            const rank = { critical: 5, high: 4, medium: 3, low: 2, baseline: 1, info: 1, unknown: 0 };
            return (rank[b] || 0) - (rank[a] || 0);
        })[0] || "unknown";
        const tools = [...new Set(items.map(item => item.tool).filter(Boolean))];
        document.getElementById("hostDetailSummary").innerHTML = `
            <div class="metric-card"><div class="metric-label">Findings</div><div class="metric-value">${items.length}</div></div>
            <div class="metric-card"><div class="metric-label">Max Severity</div><div class="metric-value">${severityBadge(maxSeverity)}</div></div>
            <div class="metric-card"><div class="metric-label">Tools</div><div class="metric-value compact">${tools.length}</div><div class="table-subtext">${compactList(tools, 5)}</div></div>
            <div class="metric-card"><div class="metric-label">Exploitable</div><div class="metric-value high">${items.filter(item => item.has_public_exploit).length}</div></div>
        `;
        document.getElementById("hostVulnRows").innerHTML = items.map(item => {
            const sev = severityClass(item.severity);
            return `
                <tr class="vuln-row-${escapeHtml(sev)} clickable-row vulnerability-detail-row" data-vulnerability-id="${escapeHtml(item.id)}">
                    <td>${scoreButton(item.priority_score, item.id)}</td>
                    <td>${severityBadge(item.severity)}</td>
                    <td><button type="button" class="link-button detail-link vulnerability-detail-link" data-vulnerability-id="${escapeHtml(item.id)}">${escapeHtml(item.title || "-")}</button></td>
                    <td>${escapeHtml(item.tool || "-")}</td>
                    <td>${escapeHtml(item.cve || "-")}</td>
                    <td>${item.has_public_exploit ? "Yes" : "No"}</td>
                </tr>
            `;
        }).join("") || '<tr><td colspan="6">No vulnerabilities found for this host.</td></tr>';
    } catch (error) {
        console.error("Failed to load host view:", error);
        document.getElementById("hostVulnRows").innerHTML =
            '<tr><td colspan="6">Error loading host vulnerabilities.</td></tr>';
    }
}

// ============================================================================
// ATTACK SURFACE TAB
// ============================================================================

async function loadAttackSurfaceView() {
    try {
        const params = new URLSearchParams({
            limit: state.asmFilters.limit,
            offset: state.asmFilters.page * state.asmFilters.limit,
        });
        if (state.asmFilters.search) params.set("search", state.asmFilters.search);
        const result = await requestJson(`/api/attack-surface?${params}`);
        const summary = result.summary || {};
        const items = result.items || [];
        state.asmFilters.total = result.total || 0;
        state.asmSummary = summary;
        updateAttackSurfaceExportLinks();

        document.getElementById("asmAssetCount").textContent = summary.asset_count ?? 0;
        document.getElementById("asmOpenPorts").textContent = summary.exposed_ports ?? 0;
        document.getElementById("asmCriticalAssets").textContent = summary.critical_assets ?? 0;
        document.getElementById("asmExploitableAssets").textContent = summary.exploitable_assets ?? 0;
        drawAttackSurfaceCanvas(summary);

        document.getElementById("attackSurfaceRows").innerHTML = items.map(asset => {
            const ports = (asset.ports || []).length
                ? (asset.ports || []).map(port => `<span class="port-chip">${escapeHtml(port.port)}/${escapeHtml(port.service || "unknown")}</span>`).join("")
                : '<span class="muted">No open ports recorded</span>';
            return `
                <tr>
                    <td>
                        ${hostLink(asset.host)}
                        <div class="table-subtext">${compactList(asset.urls, 1)}</div>
                    </td>
                    <td>${compactList(asset.ips, 4)}</td>
                    <td><div class="chip-wrap">${ports}</div></td>
                    <td>${escapeHtml(asset.vulnerability_count || 0)}</td>
                    <td>${severityBadge(asset.max_severity)}</td>
                    <td>${compactList(asset.sources, 3)}</td>
                    <td>${compactList(asset.tags, 4)}</td>
                </tr>
            `;
        }).join("") || '<tr><td colspan="7">No attack surface data found.</td></tr>';

        updatePager("asm", state.asmFilters.page, state.asmFilters.total, state.asmFilters.limit);
    } catch (error) {
        console.error("Failed to load attack surface:", error);
        document.getElementById("attackSurfaceRows").innerHTML =
            '<tr><td colspan="7">Error loading attack surface.</td></tr>';
    }
}

async function loadBbotSubdomainsView() {
    try {
        const params = new URLSearchParams({
            limit: state.bbotSubdomainFilters.limit,
            offset: state.bbotSubdomainFilters.page * state.bbotSubdomainFilters.limit,
        });
        if (state.bbotSubdomainFilters.search) params.set("search", state.bbotSubdomainFilters.search);
        if (state.bbotSubdomainFilters.parentDomain) params.set("parent_domain", state.bbotSubdomainFilters.parentDomain);
        const result = await requestJson(`/api/recon/subdomains?${params}`);
        const items = result.items || [];
        state.bbotSubdomainFilters.total = result.total || 0;
        const parentOptions = document.getElementById("bbotParentDomainOptions");
        if (parentOptions) {
            parentOptions.innerHTML = (result.domains || []).map(domain => `<option value="${escapeHtml(domain)}"></option>`).join("");
        }
        const selectAll = document.getElementById("subdomainSelectAllInput");
        if (selectAll) selectAll.checked = false;

        document.getElementById("bbotSubdomainRows").innerHTML = items.map(item => {
            const target = item.preferred_target || item.target;
            return `
                <tr>
                    <td><input class="subdomain-target-checkbox" type="checkbox" value="${escapeHtml(target)}" aria-label="Select ${escapeHtml(item.target)}" /></td>
                    <td>
                        <button type="button" class="link-button host-link" data-host="${escapeHtml(item.target)}">${escapeHtml(item.target)}</button>
                        <div class="table-subtext">${escapeHtml(item.preferred_target || item.target)}</div>
                    </td>
                    <td>${escapeHtml(item.parent_domain || "-")}</td>
                    <td>${compactList(item.urls, 2)}</td>
                    <td>${compactList(item.ips, 3)}</td>
                    <td>${compactList(item.sources, 3)}</td>
                    <td>${compactList(item.tags, 4)}</td>
                    <td>${escapeHtml(formatDateTime(item.last_seen))}</td>
                    <td><button type="button" class="btn-secondary btn-sm scan-subdomain-btn" data-target="${escapeHtml(target)}">Scan</button></td>
                </tr>
            `;
        }).join("") || '<tr><td colspan="9">No BBot subdomains found yet.</td></tr>';
        updatePager("bbotSubdomain", state.bbotSubdomainFilters.page, state.bbotSubdomainFilters.total, state.bbotSubdomainFilters.limit);
    } catch (error) {
        console.error("Failed to load BBot subdomains:", error);
        document.getElementById("bbotSubdomainRows").innerHTML =
            '<tr><td colspan="9">Error loading BBot subdomains.</td></tr>';
    }
}

function subdomainScanSelection() {
    const [kind, value] = document.getElementById("bbotSubdomainScanTypeInput").value.split(":");
    return { kind, value };
}

async function startBbotSubdomainScan(targets, label = "BBot target scan") {
    const message = document.getElementById("bbotSubdomainMessage");
    const cleanTargets = [...new Set((targets || []).map(item => String(item || "").trim()).filter(Boolean))];
    if (!cleanTargets.length) {
        message.textContent = "Select at least one subdomain.";
        return;
    }
    const scanType = subdomainScanSelection();
    const body = {
        targets: cleanTargets.join(", "),
        mode: scanType.kind === "mode" ? Number(scanType.value) : null,
        scanner: scanType.kind === "scanner" ? scanType.value : null,
        scan_name: `${label} (${cleanTargets.length})`,
        bruteforce: false,
        bruteforce_timeout: 300,
    };
    try {
        const result = await requestJson("/api/scans/start", {
            method: "POST",
            body: JSON.stringify(body),
        });
        message.textContent = `Scan ${result.scan_id} started for ${cleanTargets.length} target(s).`;
        await switchTab("debug");
        document.getElementById("debugScanSelect").value = String(result.scan_id);
        await loadScanLogs(result.scan_id);
    } catch (error) {
        message.textContent = error.message;
    }
}

// ============================================================================
// SCORING TAB
// ============================================================================

async function loadScoringView() {
    try {
        const params = new URLSearchParams({
            asset_limit: state.scoringFilters.assetLimit,
            asset_offset: state.scoringFilters.assetPage * state.scoringFilters.assetLimit,
            vuln_limit: state.scoringFilters.vulnLimit,
            vuln_offset: state.scoringFilters.vulnPage * state.scoringFilters.vulnLimit,
        });
        if (state.scoringFilters.assetSearch) params.set("asset_search", state.scoringFilters.assetSearch);
        if (state.scoringFilters.vulnSeverity) params.set("vuln_severity", state.scoringFilters.vulnSeverity);
        if (state.scoringFilters.vulnHost) params.set("vuln_host", state.scoringFilters.vulnHost);

        const result = await requestJson(`/api/scoring/overview?${params}`);
        const summary = result.summary || {};
        document.getElementById("avgPriority").textContent = summary.average_priority ?? 0;
        document.getElementById("maxPriority").textContent = summary.max_priority ?? 0;
        document.getElementById("kevCount").textContent = summary.kev_count ?? 0;
        document.getElementById("exploitCount").textContent = summary.exploitable_count ?? 0;

        document.getElementById("scoringAssetRows").innerHTML = (result.assets || []).map(asset => `
            <tr>
                <td>${hostLink(asset.host)}</td>
                <td>${escapeHtml(asset.vulnerability_count || 0)}</td>
                <td class="severity-critical">${escapeHtml(asset.critical_count || 0)}</td>
                <td class="severity-high">${escapeHtml(asset.high_count || 0)}</td>
                <td>${escapeHtml(asset.exploitable_count || 0)}</td>
                <td>${escapeHtml(asset.average_priority || 0)}</td>
                <td>${escapeHtml(asset.max_priority || 0)}</td>
            </tr>
        `).join("") || '<tr><td colspan="7">No assets scored yet.</td></tr>';

        document.getElementById("scoringVulnRows").innerHTML = (result.top_vulnerabilities || []).map(vuln => {
            const sev = (vuln.severity || "unknown").toLowerCase();
            return `
                <tr class="clickable-row vulnerability-detail-row" data-vulnerability-id="${escapeHtml(vuln.id)}">
                    <td>${scoreButton(vuln.priority_score || 0, vuln.id)}</td>
                    <td>${severityBadge(vuln.severity)}</td>
                    <td><button type="button" class="link-button detail-link vulnerability-detail-link" data-vulnerability-id="${escapeHtml(vuln.id)}">${escapeHtml(vuln.title || vuln.cve || "-")}</button></td>
                    <td>${hostLink(vuln.host)}</td>
                    <td>${escapeHtml(vuln.cve || "-")}</td>
                    <td>${vuln.has_public_exploit ? "Yes" : "No"}</td>
                    <td>${escapeHtml(vuln.score_reason || "-")}</td>
                </tr>
            `;
        }).join("") || '<tr><td colspan="7">No vulnerabilities scored yet.</td></tr>';

        state.scoringFilters.assetTotal = result.asset_total || 0;
        state.scoringFilters.vulnTotal = result.vulnerability_total || 0;
        updatePager("scoringAsset", state.scoringFilters.assetPage, state.scoringFilters.assetTotal, state.scoringFilters.assetLimit);
        updatePager("scoringVuln", state.scoringFilters.vulnPage, state.scoringFilters.vulnTotal, state.scoringFilters.vulnLimit);
    } catch (error) {
        console.error("Failed to load scoring:", error);
    }
}

// ============================================================================
// ENDPOINTS TAB
// ============================================================================

async function loadEndpointsView() {
    try {
        const filters = state.endpointFilters;
        const agentParams = new URLSearchParams({
            limit: filters.agentLimit,
            offset: filters.agentPage * filters.agentLimit,
        });
        if (filters.agentSearch) agentParams.set("search", filters.agentSearch);
        if (filters.agentStatus) agentParams.set("status", filters.agentStatus);
        const softwareParams = new URLSearchParams({
            limit: filters.softwareLimit,
            offset: filters.softwarePage * filters.softwareLimit,
        });
        if (filters.softwareSearch) softwareParams.set("search", filters.softwareSearch);
        const vulnParams = new URLSearchParams({
            limit: filters.vulnLimit,
            offset: filters.vulnPage * filters.vulnLimit,
        });
        if (filters.vulnSearch) vulnParams.set("search", filters.vulnSearch);
        if (filters.vulnSeverity) vulnParams.set("severity", filters.vulnSeverity);

        const [overview, agents, software, vulns, networkMap, tokens] = await Promise.all([
            requestJson("/api/endpoints/overview"),
            requestJson(`/api/endpoints/agents?${agentParams}`),
            requestJson(`/api/endpoints/software?${softwareParams}`),
            requestJson(`/api/endpoints/vulnerabilities?${vulnParams}`),
            requestJson("/api/endpoints/network-map"),
            roleRank(state.role) >= roleRank("tenant_admin") ? requestJson("/api/endpoints/enrollment-tokens") : Promise.resolve({ items: [] }),
        ]);

        document.getElementById("endpointAgentTotal").textContent = overview.agents || 0;
        document.getElementById("endpointOnlineTotal").textContent = overview.online_agents || 0;
        document.getElementById("endpointSoftwareTotal").textContent = overview.software || 0;
        const sev = overview.severity || {};
        document.getElementById("endpointHighTotal").textContent = (sev.critical || 0) + (sev.high || 0);
        state.endpointSeverity = sev;
        renderEndpointCharts(overview);
        renderEndpointNetworkMap(networkMap);

        renderEndpointTokens(tokens.items || []);
        renderEndpointAgents(agents.items || []);
        renderEndpointSoftware(software.items || []);
        renderEndpointVulnerabilities(vulns.items || []);
        state.endpointFilters.agentTotal = agents.total || 0;
        state.endpointFilters.softwareTotal = software.total || 0;
        state.endpointFilters.vulnTotal = vulns.total || 0;
        updatePager("endpointAgent", filters.agentPage, filters.agentTotal, filters.agentLimit);
        updatePager("endpointSoftware", filters.softwarePage, filters.softwareTotal, filters.softwareLimit);
        updatePager("endpointVuln", filters.vulnPage, filters.vulnTotal, filters.vulnLimit);
    } catch (error) {
        console.error("Failed to load endpoints:", error);
    }
}

function renderEndpointTokens(items) {
    const target = document.getElementById("endpointTokenRows");
    if (!target) return;
    if (roleRank(state.role) < roleRank("tenant_admin")) {
        target.innerHTML = "";
        return;
    }
    target.innerHTML = items.map(token => `
        <tr>
            <td>${escapeHtml(token.name || "-")}</td>
            <td><code>${escapeHtml(token.token_prefix || "-")}</code></td>
            <td>${escapeHtml(formatDateTime(token.expires_at) || "Never")}</td>
            <td>${escapeHtml(formatDateTime(token.last_used_at) || "Never")}</td>
            <td>${escapeHtml(formatDateTime(token.created_at) || "-")}</td>
            <td>${token.revoked_at ? statusBadge("revoked") : `<button type="button" class="btn-warning btn-sm revoke-endpoint-token-btn" data-token-id="${escapeHtml(token.id)}">Revoke</button>`}</td>
        </tr>
    `).join("") || '<tr><td colspan="6">No enrollment keys yet.</td></tr>';
}

function renderEndpointAgents(items) {
    const target = document.getElementById("endpointAgentRows");
    if (!target) return;
    const canAdmin = roleRank(state.role) >= roleRank("tenant_admin");
    target.innerHTML = items.map(agent => {
        const actions = [
            `<button type="button" class="btn-secondary btn-sm endpoint-agent-detail-btn" data-agent-id="${escapeHtml(agent.agent_id)}">Details</button>`,
        ];
        if (canAdmin && agent.status !== "revoked") {
            actions.push(`<button type="button" class="btn-warning btn-sm revoke-endpoint-agent-btn" data-agent-id="${escapeHtml(agent.agent_id)}">Revoke</button>`);
        }
        if (canAdmin) {
            actions.push(`<button type="button" class="btn-danger btn-sm delete-endpoint-agent-btn" data-agent-id="${escapeHtml(agent.agent_id)}">Delete</button>`);
        }
        return `
        <tr class="clickable-row endpoint-agent-row" data-agent-id="${escapeHtml(agent.agent_id)}">
            <td>${endpointAgentLink(agent.agent_id, agent.hostname || agent.agent_id)}</td>
            <td>${escapeHtml([agent.os_name, agent.os_version, agent.os_arch].filter(Boolean).join(" ") || "-")}</td>
            <td>${statusBadge(agent.status || "unknown")}</td>
            <td>${escapeHtml(agent.software_count || 0)}</td>
            <td>${escapeHtml(agent.vulnerability_count || 0)}</td>
            <td>${escapeHtml(formatDateTime(agent.last_inventory_at) || "Never")}</td>
            <td>${escapeHtml(formatDateTime(agent.last_seen_at) || "Never")}</td>
            <td class="table-actions">${actions.join("")}</td>
        </tr>
    `;
    }).join("") || '<tr><td colspan="8">No endpoint agents enrolled yet.</td></tr>';
}

function renderEndpointSoftware(items) {
    const target = document.getElementById("endpointSoftwareRows");
    if (!target) return;
    target.innerHTML = items.map(item => `
        <tr>
            <td>${endpointAgentLink(item.agent_id, item.hostname || item.agent_id)}</td>
            <td>${escapeHtml(item.name || "-")}</td>
            <td>${escapeHtml(item.version || "-")}</td>
            <td>${escapeHtml(item.vendor || "-")}</td>
            <td>${escapeHtml(item.ecosystem || "-")}</td>
            <td><code>${escapeHtml(item.purl || item.cpe || item.software_key || "-")}</code></td>
            <td>${escapeHtml(formatDateTime(item.last_seen_at) || "-")}</td>
        </tr>
    `).join("") || '<tr><td colspan="7">No software inventory yet.</td></tr>';
}

function renderEndpointVulnerabilities(items) {
    const target = document.getElementById("endpointVulnRows");
    if (!target) return;
    target.innerHTML = items.map(vuln => `
        <tr class="severity-row clickable-row endpoint-vuln-row ${escapeHtml(severityClass(vuln.severity))}" data-endpoint-vuln-id="${escapeHtml(vuln.id)}">
            <td>${severityBadge(vuln.severity || "info")}</td>
            <td><button type="button" class="link-button endpoint-vuln-link" data-endpoint-vuln-id="${escapeHtml(vuln.id)}">${escapeHtml(vuln.cve || "-")}</button></td>
            <td>${endpointAgentLink(vuln.agent_id, vuln.hostname || vuln.agent_id)}</td>
            <td>${escapeHtml(vuln.software_name || "-")}</td>
            <td>${escapeHtml(vuln.software_version || vuln.affected_version || "-")}</td>
            <td>${escapeHtml(vuln.source || "-")}</td>
            <td>${escapeHtml(vuln.confidence || 0)}%</td>
            <td>${escapeHtml(vuln.summary || "-")}</td>
        </tr>
    `).join("") || '<tr><td colspan="8">No endpoint findings matched. Name-only and broad CPE matches are intentionally suppressed.</td></tr>';
}

// ============================================================================
// SCHEDULES TAB
// ============================================================================

async function loadSchedulesView() {
    try {
        const [result, appliances] = await Promise.all([
            requestJson("/api/schedules"),
            requestJson("/api/scanner-nodes/available").catch(() => ({ items: state.scannerAppliances || [] })),
        ]);
        state.scannerAppliances = appliances.items || state.scannerAppliances || [];
        document.getElementById("scheduleRows").innerHTML = (result.items || []).map(schedule => `
            <tr>
                <td>${escapeHtml(schedule.scan_name || "-")}</td>
                <td>${escapeHtml(formatScanMode(schedule.scan_mode || schedule.scanner || "-"))}</td>
                <td>${escapeHtml(scannerApplianceName(schedule.preferred_node_id))}</td>
                <td>${escapeHtml(formatIntervalMinutes(schedule.interval_minutes))}</td>
                <td>${escapeHtml(formatDateTime(schedule.start_at))}</td>
                <td>${escapeHtml(formatDateTime(schedule.end_at))}</td>
                <td>${escapeHtml(formatDateTime(schedule.next_run_at))}</td>
                <td>${statusBadge(schedule.enabled ? "enabled" : "disabled")}</td>
                <td>
                    <button class="btn-secondary btn-sm run-schedule-btn" data-schedule-id="${schedule.id}">Run</button>
                    <button class="${schedule.enabled ? "btn-warning" : "btn-secondary"} btn-sm toggle-schedule-btn" data-schedule-id="${schedule.id}" data-enabled="${schedule.enabled ? "false" : "true"}">${schedule.enabled ? "Disable" : "Enable"}</button>
                    <button class="btn-danger btn-sm delete-schedule-btn" data-schedule-id="${schedule.id}">Delete</button>
                </td>
            </tr>
        `).join("") || '<tr><td colspan="9">No schedules yet.</td></tr>';
    } catch (error) {
        console.error("Failed to load schedules:", error);
    }
}

// ============================================================================
// NOTIFICATIONS TAB
// ============================================================================

function parseRecipients(value) {
    return [...new Set(String(value || "")
        .split(/[,\n;]/)
        .map(item => item.trim())
        .filter(Boolean))];
}

function renderRecipients() {
    const hiddenInput = document.getElementById("notificationRecipientsInput");
    const target = document.getElementById("recipientList");
    if (hiddenInput) hiddenInput.value = state.notificationRecipients.join(", ");
    if (!target) return;
    target.innerHTML = state.notificationRecipients.map(email => `
        <span class="recipient-chip">
            ${escapeHtml(email)}
            <button type="button" class="remove-recipient-btn" data-email="${escapeHtml(email)}" aria-label="Remove recipient">&times;</button>
        </span>
    `).join("") || '<span class="muted">No recipients configured.</span>';
}

function addRecipientFromInput() {
    const input = document.getElementById("recipientEmailInput");
    const message = document.getElementById("notificationMessage");
    const value = input.value.trim();
    if (!value) return;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
        if (message) message.textContent = "Vul een geldig e-mailadres in.";
        return;
    }
    state.notificationRecipients = [...new Set([...state.notificationRecipients, value])];
    input.value = "";
    renderRecipients();
    if (message) message.textContent = "";
}

async function loadNotificationSettings() {
    try {
        const settings = await requestJson("/api/notifications/settings");
        document.getElementById("notificationEnabledInput").checked = Boolean(settings.enabled);
        state.notificationRecipients = parseRecipients(settings.recipients || "");
        renderRecipients();
        document.getElementById("notificationSeverityInput").value = settings.min_severity || "high";
        document.getElementById("notifySuccessInput").checked = settings.notify_on_success !== false;
        document.getElementById("notifyFailureInput").checked = settings.notify_on_failure !== false;
    } catch (error) {
        console.error("Failed to load notifications:", error);
    }
}

// ============================================================================
// SECURITY TAB
// ============================================================================

function resetUserForm() {
    document.getElementById("adminUserEmailInput").value = "";
    document.getElementById("adminUserPasswordInput").value = "";
    document.getElementById("adminUserNameInput").value = "";
    document.getElementById("adminUserRoleInput").value = "viewer";
    const orgInput = document.getElementById("adminUserOrgInput");
    if (orgInput && state.orgDb && [...orgInput.options].some(option => option.value === state.orgDb)) {
        orgInput.value = state.orgDb;
    }
}

function renderUserRows(users) {
    const target = document.getElementById("adminUserRows");
    if (!target) return;
    if (!users.length) {
        target.innerHTML = '<tr><td colspan="6">No users yet.</td></tr>';
        return;
    }
    target.innerHTML = users.map(user => {
        const memberships = user.memberships
            ? user.memberships
            : [{
                org_name: user.org_name || state.organization,
                org_db_name: user.org_db_name || state.orgDb,
                role: user.role,
            }];
        const membershipHtml = memberships.map(m => {
            const removeButton = state.role === "platform_admin" && memberships.length > 1
                ? `<button type="button" class="inline-action remove-membership-btn" data-user-id="${escapeHtml(user.id)}" data-org-db="${escapeHtml(m.org_db_name)}">remove</button>`
                : "";
            return `<span class="membership-pill">${escapeHtml(m.org_name || m.org_db_name)} · ${escapeHtml(m.role || "-")} ${removeButton}</span>`;
        }).join("");
        const primaryMembership = memberships[0] || {};
        const editRole = user.role || primaryMembership.role || "viewer";
        const editOrg = user.org_db_name || primaryMembership.org_db_name || state.orgDb;
        return `
            <tr>
                <td>${escapeHtml(user.email || "-")}</td>
                <td>${escapeHtml(user.display_name || "-")}</td>
                <td>${user.mfa_enabled ? "On" : "Off"}</td>
                <td><div class="membership-list">${membershipHtml || "-"}</div></td>
                <td>${escapeHtml(user.last_login_at ? formatDateTime(user.last_login_at) : "Never")}</td>
                <td>
                    <button type="button" class="btn-secondary btn-sm edit-user-btn"
                        data-user-id="${escapeHtml(user.id)}"
                        data-email="${escapeHtml(user.email || "")}"
                        data-name="${escapeHtml(user.display_name || "")}"
                        data-role="${escapeHtml(editRole)}"
                        data-org-db="${escapeHtml(editOrg)}">Edit</button>
                    <button type="button" class="btn-danger btn-sm delete-user-btn"
                        data-user-id="${escapeHtml(user.id)}">Delete</button>
                </td>
            </tr>
        `;
    }).join("");
}

function renderScannerNodeRows(nodes) {
    const target = document.getElementById("scannerNodeRows");
    if (!target) return;
    if (state.role !== "platform_admin") {
        target.innerHTML = "";
        return;
    }
    if (!nodes.length) {
        target.innerHTML = '<tr><td colspan="6">No scanner nodes attached.</td></tr>';
        return;
    }
    target.innerHTML = nodes.map(node => {
        const status = node.revoked_at ? "revoked" : (node.status || "registered");
        return `
            <tr>
                <td>${escapeHtml(node.name || node.node_id || "-")}</td>
                <td><span class="status-badge status-${escapeHtml(status)}">${escapeHtml(status)}</span></td>
                <td>All scanners</td>
                <td>${escapeHtml(node.running_jobs ?? 0)} / ${escapeHtml(node.max_parallel_jobs ?? 1)}</td>
                <td>${formatDateTime(node.last_seen_at) || "Never"}</td>
                <td>
                    ${node.revoked_at
                        ? `<button class="btn-danger btn-sm delete-scanner-node-btn" data-node-id="${escapeHtml(node.node_id)}">Delete</button>`
                        : `<button class="btn-warning btn-sm revoke-scanner-node-btn" data-node-id="${escapeHtml(node.node_id)}">Revoke</button>`}
                </td>
            </tr>
        `;
    }).join("");
}

async function loadSecurityView() {
    try {
        const [mfa, sso, apiKeys, scannerNodes] = await Promise.all([
            requestJson("/api/auth/mfa/settings"),
            requestJson("/api/auth/sso/settings"),
            requestJson("/api/api-keys"),
            state.role === "platform_admin" ? requestJson("/api/scanner-nodes") : Promise.resolve({ items: [] }),
        ]);

        state.currentUserMfaEnabled = Boolean(mfa.enabled);
        state.currentSsoEnabled = Boolean(sso.enabled);
        state.currentSsoSecretConfigured = Boolean(sso.client_secret_configured);
        document.getElementById("mfaStatus").textContent = mfa.enabled ? "On" : "Off";
        document.getElementById("mfaRequiredStatus").textContent = mfa.required ? "Yes" : "No";
        document.getElementById("ssoStatus").textContent = sso.enabled ? "On" : "Off";
        document.getElementById("ssoRequiredStatus").textContent = sso.required ? "Yes" : "No";
        document.getElementById("orgMfaRequiredInput").checked = Boolean(mfa.org_required);
        document.getElementById("orgSsoRequiredInput").checked = Boolean(sso.required);
        document.getElementById("disableMfaBtn").disabled = !mfa.enabled;

        document.getElementById("ssoEnabledInput").checked = Boolean(sso.enabled);
        document.getElementById("ssoIssuerInput").value = sso.issuer || "";
        document.getElementById("ssoClientInput").value = sso.client_id || "";
        document.getElementById("ssoSecretInput").value = sso.client_secret_configured ? "********" : "";
        document.getElementById("ssoDomainInput").value = sso.allowed_domain || "";
        const platformRoleOption = document.querySelector('#adminUserRoleInput option[value="platform_admin"]');
        if (platformRoleOption) {
            platformRoleOption.hidden = state.role !== "platform_admin";
            platformRoleOption.disabled = state.role !== "platform_admin";
        }

        document.getElementById("apiKeyRows").innerHTML = (apiKeys.items || []).map(key => `
            <tr>
                <td>${escapeHtml(key.name || "-")}</td>
                <td><code>${escapeHtml(key.key_prefix || "-")}</code></td>
                <td>${escapeHtml(key.role || "-")}</td>
                <td>${escapeHtml(key.last_used_at || "Never")}</td>
                <td>${escapeHtml(key.created_at || "-")}</td>
                <td><button class="btn-secondary btn-sm revoke-api-key-btn" data-key-id="${key.id}">Revoke</button></td>
            </tr>
        `).join("") || '<tr><td colspan="6">No API keys yet.</td></tr>';
        renderScannerNodeRows(scannerNodes.items || []);

        if (roleRank(state.role) >= roleRank("tenant_admin")) {
            const [platformPolicy, orgs, users] = await Promise.all([
                state.role === "platform_admin" ? requestJson("/api/admin/auth/policy") : Promise.resolve({ mfa_required: false }),
                state.role === "platform_admin" ? requestJson("/api/admin/organizations") : Promise.resolve({ items: [{ org_name: state.organization, org_db_name: state.orgDb }] }),
                state.role === "platform_admin" ? requestJson("/api/admin/users") : requestJson("/api/users"),
            ]);
            const platformPolicyInput = document.getElementById("platformMfaRequiredInput");
            if (platformPolicyInput) platformPolicyInput.checked = Boolean(platformPolicy.mfa_required);
            const orgInput = document.getElementById("adminUserOrgInput");
            orgInput.innerHTML = (orgs.items || []).map(org => `
                <option value="${escapeHtml(org.org_db_name)}">${escapeHtml(org.org_name)} (${escapeHtml(org.org_db_name)})</option>
            `).join("");
            orgInput.disabled = state.role !== "platform_admin";
            renderUserRows(users.items || []);
        }
    } catch (error) {
        console.error("Failed to load security settings:", error);
    }
}

// ============================================================================
// MICROSOFT 365 SECURE SCORE TAB
// ============================================================================

async function loadM365View() {
    try {
        const [settings, score] = await Promise.all([
            requestJson("/api/integrations/m365/settings"),
            requestJson("/api/integrations/m365/secure-score"),
        ]);

        document.getElementById("m365EnabledInput").checked = Boolean(settings.enabled);
        document.getElementById("m365TenantInput").value = settings.tenant_id || "";
        document.getElementById("m365ClientInput").value = settings.client_id || "";
        document.getElementById("m365SecretInput").value = settings.client_secret || "";

        const summary = score.summary || {};
        document.getElementById("m365CurrentScore").textContent = summary.current_score ?? summary.currentScore ?? 0;
        document.getElementById("m365MaxScore").textContent = summary.max_score ?? summary.maxScore ?? 0;
        document.getElementById("m365LastSync").textContent = summary.last_synced_at
            ? `Last sync: ${summary.last_synced_at}`
            : "No sync yet.";

        document.getElementById("m365ControlRows").innerHTML = (score.items || []).map(item => `
            <tr>
                <td>${escapeHtml(item.control_name || "-")}</td>
                <td>${escapeHtml(item.title || "-")}</td>
                <td>${escapeHtml(item.category || "-")}</td>
                <td>${escapeHtml(item.implementation_status || "-")}</td>
                <td>${escapeHtml(item.current_score ?? "-")}</td>
                <td>${escapeHtml(item.max_score ?? "-")}</td>
            </tr>
        `).join("") || '<tr><td colspan="6">No cloud security score items synced yet.</td></tr>';
    } catch (error) {
        console.error("Failed to load cloud security score:", error);
        document.getElementById("m365Message").textContent = error.message;
    }
}

// ============================================================================
// OVERSIGHT TAB
// ============================================================================

async function loadOversightView() {
    try {
        const result = await requestJson("/api/admin/overview");
        const totals = result.totals || {};
        document.getElementById("tenantTotal").textContent = totals.organizations ?? 0;
        document.getElementById("tenantFindings").textContent = totals.vulnerabilities ?? 0;
        document.getElementById("tenantCritical").textContent = totals.critical ?? 0;
        document.getElementById("tenantExploitable").textContent = totals.exploitable ?? 0;
        document.getElementById("oversightRows").innerHTML = (result.tenants || []).map(tenant => `
            <tr>
                <td>${escapeHtml(tenant.organization || "-")}</td>
                <td>${escapeHtml(tenant.org_db || "-")}</td>
                <td>${escapeHtml(tenant.total_vulnerabilities || 0)}</td>
                <td>${escapeHtml(tenant.running_scans || 0)}</td>
                <td>${escapeHtml(tenant.critical || 0)}</td>
                <td>${escapeHtml(tenant.average_priority || 0)}</td>
                <td>${escapeHtml(tenant.max_priority || 0)}</td>
                <td><button type="button" class="btn-secondary btn-sm switch-tenant-btn" data-org-db="${escapeHtml(tenant.org_db || "")}">Open</button></td>
            </tr>
        `).join("") || '<tr><td colspan="8">No tenant data available.</td></tr>';
    } catch (error) {
        console.error("Failed to load oversight:", error);
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

function sortableValue(text) {
    const cleaned = String(text || "").trim().replace(/,/g, "");
    const number = Number(cleaned.replace(/[^0-9.-]/g, ""));
    if (cleaned && !Number.isNaN(number) && /[0-9]/.test(cleaned)) {
        return { type: "number", value: number };
    }
    const date = Date.parse(cleaned);
    if (!Number.isNaN(date) && /[a-zA-Z]{3}|T|\d{4}/.test(cleaned)) {
        return { type: "number", value: date };
    }
    return { type: "text", value: cleaned.toLowerCase() };
}

document.addEventListener("click", (event) => {
    const th = event.target.closest("table.data-table th");
    if (!th || th.closest("table.no-sort")) return;
    const table = th.closest("table");
    const tbody = table.tBodies[0];
    if (!tbody) return;
    const index = Array.from(th.parentElement.children).indexOf(th);
    const direction = th.dataset.sortDir === "asc" ? "desc" : "asc";
    Array.from(th.parentElement.children).forEach(header => {
        header.dataset.sortDir = "";
        header.classList.remove("sorted-asc", "sorted-desc");
    });
    th.dataset.sortDir = direction;
    th.classList.add(direction === "asc" ? "sorted-asc" : "sorted-desc");
    const rows = Array.from(tbody.rows).filter(row => row.cells.length > index && !row.querySelector("td[colspan]"));
    rows.sort((a, b) => {
        const av = sortableValue(a.cells[index]?.innerText);
        const bv = sortableValue(b.cells[index]?.innerText);
        const result = av.type === "number" && bv.type === "number"
            ? av.value - bv.value
            : String(av.value).localeCompare(String(bv.value));
        return direction === "asc" ? result : -result;
    });
    rows.forEach(row => tbody.appendChild(row));
});

// Tab switching
document.querySelectorAll(".tab-button").forEach(btn => {
    btn.addEventListener("click", () => {
        switchTab(btn.dataset.tab);
    });
});

document.querySelectorAll("[data-tab-shortcut]").forEach(btn => {
    btn.addEventListener("click", () => {
        switchTab(btn.dataset.tabShortcut);
    });
});

async function switchTenant(orgDb) {
    if (!orgDb || orgDb === state.orgDb) return;
    const result = await requestJson("/api/auth/select-organization", {
        method: "POST",
        body: JSON.stringify({ org_db: orgDb }),
    });
    if (handleAuthStep(result)) {
        setAuthUI();
        return;
    }
    await completeAuth(result, "Tenant switched.");
    await switchTab("dashboard");
}

document.getElementById("tenantSwitchSelect").addEventListener("change", async (event) => {
    await switchTenant(event.target.value);
});

// Login form
document.getElementById("loginForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const loginMessage = document.getElementById("loginMessage");
    loginMessage.textContent = "";

    const emailInput = document.getElementById("emailInput");
    const passwordInput = document.getElementById("passwordInput");
    const mfaCodeInput = document.getElementById("mfaCodeInput");
    const email = emailInput ? emailInput.value.trim() : "";
    const password = passwordInput ? passwordInput.value : "";
    const mfaCode = mfaCodeInput ? mfaCodeInput.value.trim() : "";

    try {
        const result = state.mfaPending
            ? await requestJson("/api/auth/mfa/verify", {
                method: "POST",
                body: JSON.stringify({ code: mfaCode }),
            })
            : state.mfaSetupPending
            ? await requestJson("/api/auth/mfa/enable", {
                method: "POST",
                body: JSON.stringify({ code: mfaCode }),
            })
            : await requestJson("/api/auth/login", {
                method: "POST",
                body: JSON.stringify({ email, password }),
            });
        if (handleAuthStep(result)) {
            return;
        }
        await completeAuth(result, result.created ? "Account aangemaakt en ingelogd." : "Ingelogd.");
    } catch (error) {
        loginMessage.textContent = error.message;
    }
});

document.getElementById("selectOrgBtn").addEventListener("click", async () => {
    const loginMessage = document.getElementById("loginMessage");
    try {
        const result = await requestJson("/api/auth/select-organization", {
            method: "POST",
            body: JSON.stringify({ org_db: document.getElementById("orgChoiceInput").value }),
        });
        if (handleAuthStep(result)) {
            return;
        }
        await completeAuth(result, "Organisatie geopend.");
    } catch (error) {
        loginMessage.textContent = error.message;
    }
});

document.getElementById("ssoLoginBtn").addEventListener("click", () => {
    const organization = document.getElementById("ssoOrgInput").value.trim();
    const loginMessage = document.getElementById("loginMessage");
    if (!organization) {
        loginMessage.textContent = "Vul de SSO-organisatie in om SSO te starten.";
        return;
    }
    window.location.href = `/api/auth/sso/start?organization=${encodeURIComponent(organization)}`;
});

// Logout
document.getElementById("logoutBtn").addEventListener("click", async () => {
    try {
        await requestJson("/api/auth/logout", { method: "POST" });
    } finally {
        state.authenticated = false;
        state.organization = "";
        state.orgDb = "";
        state.role = "";
        state.mfaPending = false;
        state.mfaSetupPending = false;
        state.organizationSelectionPending = false;
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
    const preferredNodeId = document.getElementById("applianceInput")?.value || null;
    const scanName = document.getElementById("scanNameInput").value.trim();
    const bruteforce = document.getElementById("bruteforceInput").checked;
    const recurring = document.getElementById("recurringScanInput").checked;

    if (!mode && !scanner) {
        scanMessage.textContent = "Select either a scan mode or an individual scanner.";
        return;
    }

    if (mode && scanner) {
        scanMessage.textContent = "Choose mode OR scanner, not both.";
        return;
    }

    try {
        if (recurring) {
            await requestJson("/api/schedules", {
                method: "POST",
                body: JSON.stringify({
                    targets,
                    mode: mode ? Number(mode) : null,
                    scanner: scanner || null,
                    preferred_node_id: preferredNodeId,
                    scan_name: scanName || null,
                    bruteforce,
                    bruteforce_timeout: 300,
                    interval_minutes: scheduleIntervalMinutes(),
                    start_at: dateInputToIso("scheduleStartInput"),
                    end_at: dateInputToIso("scheduleEndInput", true),
                }),
            });
            scanMessage.textContent = "Recurring scan created.";
            await loadSchedulesView();
            await refreshDashboard();
            return;
        }
        const result = await requestJson("/api/scans/start", {
            method: "POST",
            body: JSON.stringify({
                targets,
                mode: mode ? Number(mode) : null,
                scanner: scanner || null,
                preferred_node_id: preferredNodeId,
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

document.getElementById("recurringScanInput").addEventListener("change", (event) => {
    document.getElementById("recurringOptions").classList.toggle("hidden", !event.target.checked);
});

document.getElementById("endpointNetworkMapCanvas").addEventListener("click", (event) => {
    const canvas = event.currentTarget;
    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;
    const hit = (state.endpointNetworkMapHits || []).find(item => {
        if (item.w && item.h) {
            return x >= item.x && x <= item.x + item.w && y >= item.y && y <= item.y + item.h;
        }
        const dx = x - item.x;
        const dy = y - item.y;
        return Math.sqrt(dx * dx + dy * dy) <= item.r;
    });
    if (hit) openEndpointNetworkNodeDetail(hit.node);
});

document.addEventListener("click", async (event) => {
    const docsPageBtn = event.target.closest("[data-docs-page]");
    if (docsPageBtn) {
        event.preventDefault();
        switchDocsPage(docsPageBtn.dataset.docsPage);
        return;
    }

    const datePickerBtn = event.target.closest(".date-picker-btn");
    if (datePickerBtn) {
        const input = document.getElementById(datePickerBtn.dataset.dateTarget);
        if (input) {
            input.focus();
            if (typeof input.showPicker === "function") {
                input.showPicker();
            }
        }
        return;
    }

    const closeDetailBtn = event.target.closest("#detailCloseBtn");
    if (closeDetailBtn) {
        closeDetailDrawer();
        return;
    }

    if (event.target.id === "detailOverlay") {
        closeDetailDrawer();
        return;
    }

    const stopBtn = event.target.closest(".stop-scan-btn");
    if (stopBtn) {
        await requestJson(`/api/scans/${stopBtn.dataset.scanId}/stop`, { method: "POST" });
        await refreshDashboard();
        return;
    }

    const openDebugBtn = event.target.closest(".open-debug-scan-btn");
    if (openDebugBtn) {
        closeDetailDrawer();
        await switchTab("debug");
        document.getElementById("debugScanSelect").value = String(openDebugBtn.dataset.scanId);
        await loadScanLogs(openDebugBtn.dataset.scanId);
        return;
    }

    const endpointAgentBtn = event.target.closest(".endpoint-agent-link, .endpoint-agent-detail-btn");
    if (endpointAgentBtn) {
        event.preventDefault();
        await openEndpointAgentDetail(endpointAgentBtn.dataset.agentId);
        return;
    }

    const endpointVulnBtn = event.target.closest(".endpoint-vuln-link, .endpoint-vuln-row");
    if (endpointVulnBtn && endpointVulnBtn.dataset.endpointVulnId) {
        event.preventDefault();
        await openEndpointVulnerabilityDetail(endpointVulnBtn.dataset.endpointVulnId);
        return;
    }

    const hostBtn = event.target.closest(".host-link");
    if (hostBtn) {
        event.preventDefault();
        await openHostView(hostBtn.dataset.host);
        return;
    }

    const vulnerabilityDetail = event.target.closest(".vulnerability-detail-link, .vulnerability-detail-row");
    if (vulnerabilityDetail && vulnerabilityDetail.dataset.vulnerabilityId) {
        await openVulnerabilityDetail(vulnerabilityDetail.dataset.vulnerabilityId);
        return;
    }

    const scanDetail = event.target.closest(".scan-detail-row");
    if (scanDetail && scanDetail.dataset.scanId) {
        await openScanDetail(scanDetail.dataset.scanId);
        return;
    }

    const runScheduleBtn = event.target.closest(".run-schedule-btn");
    if (runScheduleBtn) {
        const result = await requestJson(`/api/schedules/${runScheduleBtn.dataset.scheduleId}/run`, { method: "POST" });
        await refreshDashboard();
        await switchTab("debug");
        document.getElementById("debugScanSelect").value = String(result.scan_id);
        await loadScanLogs(result.scan_id);
        return;
    }

    const toggleScheduleBtn = event.target.closest(".toggle-schedule-btn");
    if (toggleScheduleBtn) {
        await requestJson(`/api/schedules/${toggleScheduleBtn.dataset.scheduleId}`, {
            method: "PATCH",
            body: JSON.stringify({ enabled: toggleScheduleBtn.dataset.enabled === "true" }),
        });
        await loadSchedulesView();
        return;
    }

    const deleteScheduleBtn = event.target.closest(".delete-schedule-btn");
    if (deleteScheduleBtn) {
        await requestJson(`/api/schedules/${deleteScheduleBtn.dataset.scheduleId}`, { method: "DELETE" });
        await loadSchedulesView();
        return;
    }

    const switchTenantBtn = event.target.closest(".switch-tenant-btn");
    if (switchTenantBtn) {
        await switchTenant(switchTenantBtn.dataset.orgDb);
        return;
    }

    const editUserBtn = event.target.closest(".edit-user-btn");
    if (editUserBtn) {
        document.getElementById("adminUserEmailInput").value = editUserBtn.dataset.email || "";
        document.getElementById("adminUserPasswordInput").value = "";
        document.getElementById("adminUserNameInput").value = editUserBtn.dataset.name || "";
        document.getElementById("adminUserRoleInput").value = editUserBtn.dataset.role || "viewer";
        const orgInput = document.getElementById("adminUserOrgInput");
        if (orgInput && editUserBtn.dataset.orgDb) orgInput.value = editUserBtn.dataset.orgDb;
        document.getElementById("adminUserMessage").textContent = "Only enter a password when you want to reset it.";
        return;
    }

    const removeMembershipBtn = event.target.closest(".remove-membership-btn");
    if (removeMembershipBtn) {
        await requestJson(`/api/admin/users/${removeMembershipBtn.dataset.userId}/memberships/${removeMembershipBtn.dataset.orgDb}`, { method: "DELETE" });
        await loadSecurityView();
        return;
    }

    const deleteUserBtn = event.target.closest(".delete-user-btn");
    if (deleteUserBtn) {
        const endpoint = state.role === "platform_admin"
            ? `/api/admin/users/${deleteUserBtn.dataset.userId}`
            : `/api/users/${deleteUserBtn.dataset.userId}`;
        await requestJson(endpoint, { method: "DELETE" });
        await loadSecurityView();
        return;
    }

    const removeRecipientBtn = event.target.closest(".remove-recipient-btn");
    if (removeRecipientBtn) {
        state.notificationRecipients = state.notificationRecipients.filter(email => email !== removeRecipientBtn.dataset.email);
        renderRecipients();
        return;
    }

    const scanSubdomainBtn = event.target.closest(".scan-subdomain-btn");
    if (scanSubdomainBtn) {
        await startBbotSubdomainScan([scanSubdomainBtn.dataset.target], "BBot target");
        return;
    }

    const revokeApiKeyBtn = event.target.closest(".revoke-api-key-btn");
    if (revokeApiKeyBtn) {
        await requestJson(`/api/api-keys/${revokeApiKeyBtn.dataset.keyId}`, { method: "DELETE" });
        await loadSecurityView();
        return;
    }

    const revokeEndpointTokenBtn = event.target.closest(".revoke-endpoint-token-btn");
    if (revokeEndpointTokenBtn) {
        await requestJson(`/api/endpoints/enrollment-tokens/${revokeEndpointTokenBtn.dataset.tokenId}`, { method: "DELETE" });
        await loadEndpointsView();
        return;
    }

    const revokeEndpointAgentBtn = event.target.closest(".revoke-endpoint-agent-btn");
    if (revokeEndpointAgentBtn) {
        const confirmed = window.confirm("Revoke this endpoint agent token? The endpoint will no longer be able to submit inventory.");
        if (!confirmed) return;
        await requestJson(`/api/endpoints/agents/${encodeURIComponent(revokeEndpointAgentBtn.dataset.agentId)}/revoke`, { method: "POST" });
        await loadEndpointsView();
        return;
    }

    const deleteEndpointAgentBtn = event.target.closest(".delete-endpoint-agent-btn");
    if (deleteEndpointAgentBtn) {
        const confirmed = window.confirm("Delete this local endpoint record, including its inventory and endpoint findings?");
        if (!confirmed) return;
        await requestJson(`/api/endpoints/agents/${encodeURIComponent(deleteEndpointAgentBtn.dataset.agentId)}`, { method: "DELETE" });
        closeDetailDrawer();
        await loadEndpointsView();
        return;
    }

    const endpointAgentRow = event.target.closest(".endpoint-agent-row");
    if (endpointAgentRow && endpointAgentRow.dataset.agentId) {
        await openEndpointAgentDetail(endpointAgentRow.dataset.agentId);
        return;
    }

    const revokeScannerNodeBtn = event.target.closest(".revoke-scanner-node-btn");
    if (revokeScannerNodeBtn) {
        await requestJson(`/api/scanner-nodes/${revokeScannerNodeBtn.dataset.nodeId}`, { method: "DELETE" });
        await loadSecurityView();
        await loadScannerApplianceOptions();
        return;
    }

    const deleteScannerNodeBtn = event.target.closest(".delete-scanner-node-btn");
    if (deleteScannerNodeBtn) {
        await requestJson(`/api/scanner-nodes/${deleteScannerNodeBtn.dataset.nodeId}/record`, { method: "DELETE" });
        await loadSecurityView();
        await loadScannerApplianceOptions();
    }
});

document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
        closeDetailDrawer();
    }
});

window.addEventListener("resize", () => {
    renderVulnerabilityCharts();
    renderEndpointCharts({ severity: state.endpointSeverity || {} });
    drawEndpointNetworkMap(state.endpointNetworkMap || {});
    drawScanActivityCanvas();
    drawAttackSurfaceCanvas(state.asmSummary);
});

document.getElementById("notificationForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = document.getElementById("notificationMessage");
    message.textContent = "";
    try {
        await requestJson("/api/notifications/settings", {
            method: "PATCH",
            body: JSON.stringify({
                enabled: document.getElementById("notificationEnabledInput").checked,
                recipients: state.notificationRecipients.join(", ") || null,
                min_severity: document.getElementById("notificationSeverityInput").value,
                notify_on_success: document.getElementById("notifySuccessInput").checked,
                notify_on_failure: document.getElementById("notifyFailureInput").checked,
            }),
        });
        message.textContent = "Notification settings saved.";
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("addRecipientBtn").addEventListener("click", addRecipientFromInput);
document.getElementById("recipientEmailInput").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
        event.preventDefault();
        addRecipientFromInput();
    }
});

document.getElementById("testNotificationBtn").addEventListener("click", async () => {
    const message = document.getElementById("notificationMessage");
    try {
        await requestJson("/api/notifications/test", { method: "POST" });
        message.textContent = "Test notification sent or skipped if SMTP is not configured.";
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("setupSsoBtn").addEventListener("click", () => {
    const panel = document.getElementById("ssoSetupPanel");
    const willOpen = panel.classList.contains("hidden");
    closeAuthSetupPanels(willOpen ? "ssoSetupPanel" : "");
    panel.classList.toggle("hidden", !willOpen);
});

document.getElementById("setupMfaBtn").addEventListener("click", async () => {
    const message = document.getElementById("mfaSettingsMessage");
    const panel = document.getElementById("mfaSetupPanel");
    const willOpen = panel.classList.contains("hidden");
    if (!willOpen) {
        closeAuthSetupPanels();
        return;
    }
    closeAuthSetupPanels("mfaSetupPanel");
    if (state.currentUserMfaEnabled) {
        const confirmed = window.confirm("MFA is already enabled. Setting it up again will replace your current authenticator secret. Continue?");
        if (!confirmed) {
            closeAuthSetupPanels();
            message.textContent = "MFA setup cancelled.";
            return;
        }
    }
    try {
        const setup = await requestJson("/api/auth/mfa/setup", { method: "POST" });
        panel.classList.remove("hidden");
        document.getElementById("mfaSecretOutput").textContent = setup.secret;
        document.getElementById("mfaOtpAuthOutput").value = setup.otpauth_url;
        setQrImage("mfaQrImage", setup.qr_data_uri);
        message.textContent = "MFA secret generated. Confirm with a current authenticator code.";
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("enableMfaBtn").addEventListener("click", async () => {
    const message = document.getElementById("mfaSettingsMessage");
    try {
        await requestJson("/api/auth/mfa/enable", {
            method: "POST",
            body: JSON.stringify({ code: document.getElementById("mfaEnableCodeInput").value.trim() }),
        });
        message.textContent = "MFA enabled.";
        closeAuthSetupPanels();
        await loadSecurityView();
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("disableMfaBtn").addEventListener("click", async () => {
    const message = document.getElementById("mfaSettingsMessage");
    try {
        await requestJson("/api/auth/mfa/disable", { method: "POST" });
        message.textContent = "MFA disabled.";
        closeAuthSetupPanels();
        await loadSecurityView();
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("saveOrgMfaPolicyBtn").addEventListener("click", async () => {
    const message = document.getElementById("authPolicyMessage");
    const requireMfa = document.getElementById("orgMfaRequiredInput").checked;
    const requireSso = document.getElementById("orgSsoRequiredInput").checked;
    if (requireMfa && !state.currentUserMfaEnabled) {
        message.textContent = "Enable MFA on your own account before requiring it by policy.";
        return;
    }
    if (requireSso && (!state.currentSsoEnabled || !state.currentSsoSecretConfigured)) {
        message.textContent = "Configure and enable SSO before requiring it by policy.";
        document.getElementById("ssoSetupPanel").classList.remove("hidden");
        return;
    }
    try {
        await requestJson("/api/auth/organization-policy", {
            method: "PATCH",
            body: JSON.stringify({ mfa_required: requireMfa, sso_required: requireSso }),
        });
        message.textContent = "Enforcement policy saved.";
        await loadSecurityView();
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("savePlatformMfaPolicyBtn").addEventListener("click", async () => {
    const message = document.getElementById("authPolicyMessage");
    const requireMfa = document.getElementById("platformMfaRequiredInput").checked;
    if (requireMfa && !state.currentUserMfaEnabled) {
        message.textContent = "Enable MFA on your own account before requiring it by policy.";
        return;
    }
    try {
        await requestJson("/api/admin/auth/policy", {
            method: "PATCH",
            body: JSON.stringify({ mfa_required: requireMfa }),
        });
        message.textContent = "Platform policy saved.";
        await loadSecurityView();
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("saveAdminUserBtn").addEventListener("click", async () => {
    const message = document.getElementById("adminUserMessage");
    try {
        const isPlatformAdmin = state.role === "platform_admin";
        const password = document.getElementById("adminUserPasswordInput").value;
        const passwordError = passwordPolicyError(password);
        if (passwordError) {
            message.textContent = passwordError;
            return;
        }
        const payload = {
            email: document.getElementById("adminUserEmailInput").value.trim(),
            password: password || null,
            display_name: document.getElementById("adminUserNameInput").value.trim() || null,
            role: document.getElementById("adminUserRoleInput").value,
        };
        if (isPlatformAdmin) {
            payload.org_db = document.getElementById("adminUserOrgInput").value;
        }
        const result = await requestJson(isPlatformAdmin ? "/api/admin/users" : "/api/users", {
            method: "POST",
            body: JSON.stringify(payload),
        });
        message.textContent = result.user?.email ? `Saved user ${result.user.email}.` : "User saved.";
        resetUserForm();
        await loadSecurityView();
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("clearAdminUserBtn").addEventListener("click", () => {
    resetUserForm();
    document.getElementById("adminUserMessage").textContent = "";
});

document.getElementById("ssoSettingsForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = document.getElementById("ssoSettingsMessage");
    try {
        await requestJson("/api/auth/sso/settings", {
            method: "PATCH",
            body: JSON.stringify({
                enabled: document.getElementById("ssoEnabledInput").checked,
                issuer: document.getElementById("ssoIssuerInput").value.trim() || null,
                client_id: document.getElementById("ssoClientInput").value.trim() || null,
                client_secret: document.getElementById("ssoSecretInput").value.trim() || null,
                allowed_domain: document.getElementById("ssoDomainInput").value.trim() || null,
            }),
        });
        message.textContent = "SSO settings saved.";
        await loadSecurityView();
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("createApiKeyBtn").addEventListener("click", async () => {
    const message = document.getElementById("apiKeyMessage");
    const name = document.getElementById("apiKeyNameInput").value.trim();
    if (!name) {
        message.textContent = "Enter an API key name.";
        return;
    }
    try {
        const result = await requestJson("/api/api-keys", {
            method: "POST",
            body: JSON.stringify({ name, role: document.getElementById("apiKeyRoleInput").value }),
        });
        document.getElementById("apiKeyCreatedPanel").classList.remove("hidden");
        document.getElementById("apiKeyCreatedOutput").textContent = result.key;
        document.getElementById("apiKeyNameInput").value = "";
        message.textContent = "API key created.";
        await loadSecurityView();
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("createEndpointTokenBtn").addEventListener("click", async () => {
    const message = document.getElementById("endpointTokenMessage");
    const name = document.getElementById("endpointTokenNameInput").value.trim() || "Endpoint enrollment";
    const expiresDays = Number(document.getElementById("endpointTokenDaysInput").value || 30);
    message.textContent = "";
    try {
        const result = await requestJson("/api/endpoints/enrollment-tokens", {
            method: "POST",
            body: JSON.stringify({ name, expires_days: expiresDays }),
        });
        document.getElementById("endpointInstallPanel").classList.remove("hidden");
        document.getElementById("endpointInstallOutput").value = result.install_command || result.token || "";
        document.getElementById("endpointTokenNameInput").value = "";
        message.textContent = "Endpoint enrollment key created.";
        await loadEndpointsView();
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("endpointAgentSearchBtn").addEventListener("click", async () => {
    state.endpointFilters.agentSearch = document.getElementById("endpointAgentSearchInput").value.trim();
    state.endpointFilters.agentStatus = document.getElementById("endpointAgentStatusInput").value;
    state.endpointFilters.agentPage = 0;
    await loadEndpointsView();
});

document.getElementById("endpointSoftwareSearchBtn").addEventListener("click", async () => {
    state.endpointFilters.softwareSearch = document.getElementById("endpointSoftwareSearchInput").value.trim();
    state.endpointFilters.softwarePage = 0;
    await loadEndpointsView();
});

document.getElementById("endpointVulnSearchBtn").addEventListener("click", async () => {
    state.endpointFilters.vulnSearch = document.getElementById("endpointVulnSearchInput").value.trim();
    state.endpointFilters.vulnSeverity = document.getElementById("endpointVulnSeverityInput").value;
    state.endpointFilters.vulnPage = 0;
    await loadEndpointsView();
});

document.getElementById("endpointAgentPrevBtn").addEventListener("click", () => {
    if (state.endpointFilters.agentPage > 0) {
        state.endpointFilters.agentPage--;
        loadEndpointsView();
    }
});

document.getElementById("endpointAgentNextBtn").addEventListener("click", () => {
    const maxPage = Math.ceil(state.endpointFilters.agentTotal / state.endpointFilters.agentLimit);
    if (state.endpointFilters.agentPage < maxPage - 1) {
        state.endpointFilters.agentPage++;
        loadEndpointsView();
    }
});

document.getElementById("endpointSoftwarePrevBtn").addEventListener("click", () => {
    if (state.endpointFilters.softwarePage > 0) {
        state.endpointFilters.softwarePage--;
        loadEndpointsView();
    }
});

document.getElementById("endpointSoftwareNextBtn").addEventListener("click", () => {
    const maxPage = Math.ceil(state.endpointFilters.softwareTotal / state.endpointFilters.softwareLimit);
    if (state.endpointFilters.softwarePage < maxPage - 1) {
        state.endpointFilters.softwarePage++;
        loadEndpointsView();
    }
});

document.getElementById("endpointVulnPrevBtn").addEventListener("click", () => {
    if (state.endpointFilters.vulnPage > 0) {
        state.endpointFilters.vulnPage--;
        loadEndpointsView();
    }
});

document.getElementById("endpointVulnNextBtn").addEventListener("click", () => {
    const maxPage = Math.ceil(state.endpointFilters.vulnTotal / state.endpointFilters.vulnLimit);
    if (state.endpointFilters.vulnPage < maxPage - 1) {
        state.endpointFilters.vulnPage++;
        loadEndpointsView();
    }
});

document.getElementById("recalculateEndpointVulnsBtn").addEventListener("click", async () => {
    const message = document.getElementById("endpointVulnMessage");
    message.textContent = "Recalculating endpoint findings...";
    try {
        const result = await requestJson("/api/endpoints/vulnerabilities/recalculate", { method: "POST" });
        message.textContent = `Recalculated ${result.vulnerabilities || 0} endpoint findings across ${result.agents || 0} agents.`;
        await loadEndpointsView();
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("createScannerNodeBtn").addEventListener("click", async () => {
    const message = document.getElementById("scannerNodeMessage");
    const name = document.getElementById("scannerNodeNameInput").value.trim();
    const maxParallel = Number(document.getElementById("scannerParallelInput").value || 1);
    if (!name) {
        message.textContent = "Enter a scanner name.";
        return;
    }
    try {
        const result = await requestJson("/api/scanner-nodes", {
            method: "POST",
            body: JSON.stringify({
                name,
                max_parallel_jobs: maxParallel,
            }),
        });
        document.getElementById("scannerAttachPanel").classList.remove("hidden");
        document.getElementById("scannerAttachOutput").value = result.attach_command || result.token || "";
        document.getElementById("scannerNodeNameInput").value = "";
        message.textContent = `Scanner attach key created for ${result.node_id}.`;
        await loadSecurityView();
        await loadScannerApplianceOptions();
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("m365SettingsForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = document.getElementById("m365Message");
    message.textContent = "";
    try {
        await requestJson("/api/integrations/m365/settings", {
            method: "PATCH",
            body: JSON.stringify({
                enabled: document.getElementById("m365EnabledInput").checked,
                tenant_id: document.getElementById("m365TenantInput").value.trim() || null,
                client_id: document.getElementById("m365ClientInput").value.trim() || null,
                client_secret: document.getElementById("m365SecretInput").value.trim() || null,
            }),
        });
        message.textContent = "Cloud security settings saved.";
        await loadM365View();
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("syncM365Btn").addEventListener("click", async () => {
    const message = document.getElementById("m365Message");
    message.textContent = "Syncing cloud security score...";
    try {
        const result = await requestJson("/api/integrations/m365/secure-score/sync", { method: "POST" });
        message.textContent = `Synced ${result.stored || 0} cloud security controls.`;
        await loadM365View();
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("recalculateScoresBtn").addEventListener("click", async () => {
    await requestJson("/api/scoring/recalculate", { method: "POST" });
    await loadScoringView();
});

document.getElementById("asmSearchBtn").addEventListener("click", () => {
    state.asmFilters.search = document.getElementById("asmSearchInput").value.trim();
    state.asmFilters.page = 0;
    loadAttackSurfaceView();
});

document.getElementById("asmSearchInput").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
        event.preventDefault();
        document.getElementById("asmSearchBtn").click();
    }
});

document.getElementById("asmPrevBtn").addEventListener("click", () => {
    if (state.asmFilters.page > 0) {
        state.asmFilters.page--;
        loadAttackSurfaceView();
    }
});

document.getElementById("asmNextBtn").addEventListener("click", () => {
    const maxPage = Math.ceil(state.asmFilters.total / state.asmFilters.limit);
    if (state.asmFilters.page < maxPage - 1) {
        state.asmFilters.page++;
        loadAttackSurfaceView();
    }
});

document.getElementById("bbotSubdomainSearchBtn").addEventListener("click", () => {
    state.bbotSubdomainFilters.parentDomain = document.getElementById("bbotParentDomainInput").value.trim();
    state.bbotSubdomainFilters.search = document.getElementById("bbotSubdomainSearchInput").value.trim();
    state.bbotSubdomainFilters.page = 0;
    loadBbotSubdomainsView();
});

document.getElementById("bbotParentDomainInput").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
        event.preventDefault();
        document.getElementById("bbotSubdomainSearchBtn").click();
    }
});

document.getElementById("bbotSubdomainSearchInput").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
        event.preventDefault();
        document.getElementById("bbotSubdomainSearchBtn").click();
    }
});

document.getElementById("bbotSubdomainPrevBtn").addEventListener("click", () => {
    if (state.bbotSubdomainFilters.page > 0) {
        state.bbotSubdomainFilters.page--;
        loadBbotSubdomainsView();
    }
});

document.getElementById("bbotSubdomainNextBtn").addEventListener("click", () => {
    const maxPage = Math.ceil(state.bbotSubdomainFilters.total / state.bbotSubdomainFilters.limit);
    if (state.bbotSubdomainFilters.page < maxPage - 1) {
        state.bbotSubdomainFilters.page++;
        loadBbotSubdomainsView();
    }
});

document.getElementById("subdomainSelectAllInput").addEventListener("change", (event) => {
    document.querySelectorAll(".subdomain-target-checkbox").forEach(input => {
        input.checked = event.target.checked;
    });
});

document.getElementById("scanSelectedSubdomainsBtn").addEventListener("click", () => {
    const targets = Array.from(document.querySelectorAll(".subdomain-target-checkbox:checked")).map(input => input.value);
    startBbotSubdomainScan(targets, "BBot selected targets");
});

document.getElementById("scanAllSubdomainsBtn").addEventListener("click", async () => {
    const params = new URLSearchParams({ limit: 500, offset: 0 });
    if (state.bbotSubdomainFilters.search) params.set("search", state.bbotSubdomainFilters.search);
    if (state.bbotSubdomainFilters.parentDomain) params.set("parent_domain", state.bbotSubdomainFilters.parentDomain);
    const result = await requestJson(`/api/recon/subdomains?${params}`);
    const targets = (result.items || []).map(item => item.preferred_target || item.target);
    await startBbotSubdomainScan(targets, "BBot all targets");
});

document.getElementById("showSubdomainsBtn").addEventListener("click", () => {
    document.getElementById("bbotSubdomainsCard").scrollIntoView({ behavior: "smooth", block: "start" });
});

document.getElementById("scoringAssetFilterBtn").addEventListener("click", () => {
    state.scoringFilters.assetSearch = document.getElementById("scoringAssetSearchInput").value.trim();
    state.scoringFilters.assetPage = 0;
    loadScoringView();
});

document.getElementById("scoringVulnFilterBtn").addEventListener("click", () => {
    state.scoringFilters.vulnSeverity = document.getElementById("scoringSeverityInput").value;
    state.scoringFilters.vulnHost = document.getElementById("scoringHostInput").value.trim();
    state.scoringFilters.vulnPage = 0;
    loadScoringView();
});

document.getElementById("scoringAssetPrevBtn").addEventListener("click", () => {
    if (state.scoringFilters.assetPage > 0) {
        state.scoringFilters.assetPage--;
        loadScoringView();
    }
});

document.getElementById("scoringAssetNextBtn").addEventListener("click", () => {
    const maxPage = Math.ceil(state.scoringFilters.assetTotal / state.scoringFilters.assetLimit);
    if (state.scoringFilters.assetPage < maxPage - 1) {
        state.scoringFilters.assetPage++;
        loadScoringView();
    }
});

document.getElementById("scoringVulnPrevBtn").addEventListener("click", () => {
    if (state.scoringFilters.vulnPage > 0) {
        state.scoringFilters.vulnPage--;
        loadScoringView();
    }
});

document.getElementById("scoringVulnNextBtn").addEventListener("click", () => {
    const maxPage = Math.ceil(state.scoringFilters.vulnTotal / state.scoringFilters.vulnLimit);
    if (state.scoringFilters.vulnPage < maxPage - 1) {
        state.scoringFilters.vulnPage++;
        loadScoringView();
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
applyRoleUI();
if (state.authenticated) {
    refreshDashboard();
    loadFilterOptions();
    setInterval(refreshDashboard, 20000);
}
