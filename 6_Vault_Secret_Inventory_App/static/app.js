const state = {
  namespaceFilter: "",
  namespaces: [],
  secrets: [],
  alerts: [],
  events: [],
  eventsRunning: false,
  eventsError: ""
};

const configForm = document.getElementById("config-form");
const scanBtn = document.getElementById("scan-btn");
const tabsEl = document.getElementById("namespace-tabs");
const tbodyEl = document.getElementById("secrets-body");
const summaryEl = document.getElementById("summary");
const alertsEl = document.getElementById("alerts-json");
const eventsEl = document.getElementById("events-json");
const statusEl = document.getElementById("scan-status");

function toLocalDate(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "-";
  return d.toLocaleString();
}

function renderTabs() {
  tabsEl.innerHTML = "";
  const allBtn = document.createElement("button");
  allBtn.className = `tab ${state.namespaceFilter === "" ? "active" : ""}`;
  allBtn.textContent = "Todos";
  allBtn.onclick = () => {
    state.namespaceFilter = "";
    renderTable();
    renderTabs();
  };
  tabsEl.appendChild(allBtn);

  state.namespaces.forEach((ns) => {
    const btn = document.createElement("button");
    btn.className = `tab ${state.namespaceFilter === ns ? "active" : ""}`;
    btn.textContent = ns || "root";
    btn.onclick = () => {
      state.namespaceFilter = ns;
      renderTable();
      renderTabs();
    };
    tabsEl.appendChild(btn);
  });
}

function renderTable() {
  const records = state.namespaceFilter
    ? state.secrets.filter((s) => (s.namespace || "") === state.namespaceFilter)
    : state.secrets;

  tbodyEl.innerHTML = "";
  records.forEach((row) => {
    const tr = document.createElement("tr");
    tr.className = row.severity || "green";
    const md = row.customMetadata || {};
    tr.innerHTML = `
      <td>${row.namespace || "root"}</td>
      <td>${row.mount || "-"}</td>
      <td>${row.secretPath || "-"}</td>
      <td>${row.kvVersion || "-"}</td>
      <td>${toLocalDate(row.createdTime)}</td>
      <td>${toLocalDate(row.updatedTime)}</td>
      <td>${row.ageMinutes ?? "-"}</td>
      <td>${md.owner || "-"}</td>
      <td>${md.email || "-"}</td>
      <td>${md.app || "-"}</td>
      <td>${row.currentVersion || "-"}</td>
    `;
    tbodyEl.appendChild(tr);
  });

  summaryEl.textContent = `${records.length} secretos mostrados (${state.secrets.length} total)`;
}

function renderAlerts() {
  alertsEl.textContent = JSON.stringify(state.alerts, null, 2);
}

function renderEvents() {
  const payload = {
    running: state.eventsRunning,
    error: state.eventsError || null,
    total: state.events.length,
    events: state.events
  };
  eventsEl.textContent = JSON.stringify(payload, null, 2);
}

async function refreshData() {
  const nsRes = await fetch("/api/namespaces");
  const nsData = await nsRes.json();
  state.namespaces = nsData.namespaces || [];

  const secRes = await fetch("/api/secrets");
  const secData = await secRes.json();
  state.secrets = secData.secrets || [];
  statusEl.textContent = secData.lastScan ? `Ultimo escaneo: ${toLocalDate(secData.lastScan)}` : "Sin escaneo";

  const alertRes = await fetch("/api/alerts");
  const alertData = await alertRes.json();
  state.alerts = alertData.alerts || [];

  const eventRes = await fetch("/api/events");
  const eventData = await eventRes.json();
  state.events = eventData.events || [];
  state.eventsRunning = !!eventData.running;
  state.eventsError = eventData.error || "";

  renderTabs();
  renderTable();
  renderAlerts();
  renderEvents();
}

configForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(configForm);
  const payload = {
    vaultAddress: (form.get("vaultAddress") || "").toString(),
    periodicToken: (form.get("periodicToken") || "").toString(),
    sourceNamespace: (form.get("sourceNamespace") || "").toString(),
    orangeThresholdMinutes: Number(form.get("orangeThresholdMinutes") || 30),
    redThresholdMinutes: Number(form.get("redThresholdMinutes") || 60),
    webhookUrl: (form.get("webhookUrl") || "").toString(),
    scanIntervalSeconds: Number(form.get("scanIntervalSeconds") || 120),
    eventTopic: (form.get("eventTopic") || "").toString(),
    eventFilter: (form.get("eventFilter") || "").toString()
  };

  statusEl.textContent = "Guardando configuracion...";
  const res = await fetch("/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!res.ok) {
    const msg = await res.text();
    statusEl.textContent = `Error: ${msg}`;
    return;
  }

  statusEl.textContent = "Configuracion guardada. Ejecutando escaneo...";
  await runScan();
});

async function runScan() {
  const res = await fetch("/api/scan", { method: "POST" });
  if (!res.ok) {
    const msg = await res.text();
    statusEl.textContent = `Error escaneo: ${msg}`;
    return;
  }
  await refreshData();
}

scanBtn.addEventListener("click", runScan);
refreshData();
setInterval(refreshData, 20000);
