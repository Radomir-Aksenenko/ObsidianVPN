const device = document.querySelector(".device");
const screens = [...document.querySelectorAll(".screen")];
const tabs = [...document.querySelectorAll(".tab")];
const profileDialog = document.querySelector("#profileDialog");
const protocolDialog = document.querySelector("#protocolDialog");
const toast = document.querySelector("#toast");

const state = {
  connection: "disconnected", // "disconnected" | "connecting" | "connected"
  selectedId: "helsinki",
  connectedAt: null,
  timer: null,
  sessionTimer: null,
  speedTimer: null,
  servers: [
    { id: "helsinki", code: "FI", city: "Хельсинки", endpoint: "fi.obsidian.test:443", latency: 42 },
    { id: "stockholm", code: "SE", city: "Стокгольм", endpoint: "91.204.12.44:443", latency: 51 },
    { id: "frankfurt", code: "DE", city: "Франкфурт", endpoint: "de.obsidian.test:443", latency: 68 },
    { id: "amsterdam", code: "NL", city: "Амстердам", endpoint: "nl.obsidian.test:443", latency: 55 }
  ],
  logs: [
    "[OK] Obsidian Reality Engine инициализирован",
    "[NET] Шлюз: 1280 MTU · ChaCha20-Poly1305",
    "[INFO] Выбран сервер Хельсинки (42 ms)"
  ]
};

// MARK: - Navigation

function navigate(target) {
  screens.forEach((screen) => screen.classList.toggle("active", screen.dataset.screen === target));
  tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.target === target));
}

tabs.forEach((tab) => {
  tab.addEventListener("click", () => navigate(tab.dataset.target));
});

// MARK: - Selected Server & Server List

function selectedServer() {
  return state.servers.find((s) => s.id === state.selectedId) || state.servers[0];
}

function renderSelectedServer() {
  const server = selectedServer();
  const codeEl = document.querySelector("#selectedCode");
  const cityEl = document.querySelector("#selectedCity");
  const epEl = document.querySelector("#selectedEndpoint");
  const latEl = document.querySelector("#selectedLatency");

  if (codeEl) codeEl.textContent = server.code;
  if (cityEl) cityEl.textContent = server.city;
  if (epEl) epEl.textContent = server.endpoint;
  if (latEl) latEl.textContent = `${server.latency} ms`;
}

function renderServers(filterText = "") {
  const list = document.querySelector("#serverList");
  if (!list) return;
  list.innerHTML = "";

  const query = filterText.trim().toLowerCase();
  const filtered = query
    ? state.servers.filter((s) => s.city.toLowerCase().includes(query) || s.endpoint.toLowerCase().includes(query))
    : state.servers;

  filtered.forEach((server) => {
    const isSelected = server.id === state.selectedId;
    const row = document.createElement("button");
    row.className = `server-row${isSelected ? " selected" : ""}`;
    row.innerHTML = `
      <div class="country-squircle">
        <span>${server.code}</span>
      </div>
      <div class="server-row-meta">
        <strong>${server.city}</strong>
        <small>${server.endpoint}</small>
      </div>
      <div class="latency-chip">
        <span class="latency-dot"></span>
        <span>${server.latency} ms</span>
      </div>
      <span class="server-row-check">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
      </span>
    `;

    row.addEventListener("click", () => {
      state.selectedId = server.id;
      renderServers(filterText);
      renderSelectedServer();
      addLog(`[INFO] Выбран сервер: ${server.city} (${server.endpoint})`);
      showToast(`Выбран сервер: ${server.city}`);
      setTimeout(() => navigate("home"), 280);
    });

    list.appendChild(row);
  });
}

const searchInput = document.querySelector("#searchInput");
if (searchInput) {
  searchInput.addEventListener("input", (e) => {
    renderServers(e.target.value);
  });
}

// MARK: - Connection & Liquid Glass State

function setConnection(next) {
  state.connection = next;
  device.classList.toggle("connecting", next === "connecting");
  device.classList.toggle("connected", next === "connected");

  const capsuleText = document.querySelector("#statusCapsuleText");
  const actionLabel = document.querySelector("#connectLabel");
  const subtitle = document.querySelector("#bubbleStatusText");

  if (next === "connecting") {
    if (capsuleText) capsuleText.textContent = "ПОДКЛЮЧЕНИЕ...";
    if (actionLabel) actionLabel.textContent = "ОТМЕНА";
    if (subtitle) subtitle.textContent = "Шифрование...";
    addLog(`[NET] Запуск Reality-туннеля к ${selectedServer().city}...`);
    return;
  }

  if (next === "connected") {
    if (capsuleText) capsuleText.textContent = "ЗАЩИЩЕНО REALITY";
    if (actionLabel) actionLabel.textContent = "ОТКЛЮЧИТЬ";
    if (subtitle) subtitle.textContent = "Защищено";
    state.connectedAt = Date.now();
    startTelemetry();
    addLog(`[OK] Туннель активен. Сетевой трафик зашифрован ChaCha20.`);
    showToast(`Защищено через ${selectedServer().city}`);
    return;
  }

  // Disconnected
  if (capsuleText) capsuleText.textContent = "ГОТОВ К РАБОТЕ";
  if (actionLabel) actionLabel.textContent = "ПОДКЛЮЧИТЬ";
  if (subtitle) subtitle.textContent = "Obsidian Core";
  stopTelemetry();
  addLog("[INFO] Туннель остановлен. Трафик идёт напрямую.");
}

function toggleConnection() {
  if (state.connection === "connecting") {
    clearTimeout(state.timer);
    setConnection("disconnected");
    return;
  }

  if (state.connection === "connected") {
    setConnection("disconnected");
    return;
  }

  setConnection("connecting");
  state.timer = setTimeout(() => {
    setConnection("connected");
  }, 1600);
}

const connectButton = document.querySelector("#connectButton");
if (connectButton) {
  connectButton.addEventListener("click", toggleConnection);
}

// MARK: - Telemetry Simulation

function startTelemetry() {
  stopTelemetry();

  state.sessionTimer = setInterval(() => {
    if (!state.connectedAt) return;
    const sec = Math.floor((Date.now() - state.connectedAt) / 1000);
    const h = String(Math.floor(sec / 3600)).padStart(2, "0");
    const m = String(Math.floor((sec % 3600) / 60)).padStart(2, "0");
    const s = String(sec % 60).padStart(2, "0");
    const sessionEl = document.querySelector("#sessionMetric");
    if (sessionEl) sessionEl.textContent = `${h}:${m}:${s}`;
  }, 1000);

  state.speedTimer = setInterval(() => {
    const mbps = (28 + Math.random() * 45).toFixed(1);
    const speedEl = document.querySelector("#speedMetric");
    if (speedEl) speedEl.textContent = `${mbps} МБ/с`;
  }, 1200);
}

function stopTelemetry() {
  clearInterval(state.sessionTimer);
  clearInterval(state.speedTimer);
  const sessionEl = document.querySelector("#sessionMetric");
  const speedEl = document.querySelector("#speedMetric");
  if (sessionEl) sessionEl.textContent = "00:00:00";
  if (speedEl) speedEl.textContent = "0 Б/с";
}

// MARK: - Ping Measure

function measurePing() {
  const pingEl = document.querySelector("#pingMetric");
  const latEl = document.querySelector("#selectedLatency");
  if (pingEl) pingEl.textContent = "...";
  showToast("Замер задержки шлюза...");

  setTimeout(() => {
    const s = selectedServer();
    const newLatency = Math.max(18, s.latency + Math.floor((Math.random() - 0.5) * 8));
    s.latency = newLatency;
    if (pingEl) pingEl.textContent = `${newLatency} мс`;
    if (latEl) latEl.textContent = `${newLatency} ms`;
    renderServers(searchInput ? searchInput.value : "");
    addLog(`[NET] Пинг до ${s.city}: ${newLatency} ms (ICMP/UDP reply)`);
  }, 600);
}

const measurePingBtn = document.querySelector("#actionMeasurePing");
if (measurePingBtn) measurePingBtn.addEventListener("click", measurePing);

const pingTile = document.querySelector("#pingTile");
if (pingTile) pingTile.addEventListener("click", measurePing);

// MARK: - Network Logs Console

function addLog(text) {
  state.logs.push(text);
  const terminal = document.querySelector("#logsTerminal");
  if (!terminal) return;

  const p = document.createElement("p");
  p.className = "log-entry";
  if (text.includes("[OK]")) p.classList.add("log-ok");
  else if (text.includes("[INFO]")) p.classList.add("log-accent");
  else if (text.includes("[FAIL]")) p.classList.add("log-fail");
  p.textContent = text;
  terminal.appendChild(p);
  terminal.scrollTop = terminal.scrollHeight;
}

const logsCard = document.querySelector("#logsCard");
const logsToggleBtn = document.querySelector("#logsToggleBtn");
const actionLogs = document.querySelector("#actionLogs");

function toggleLogs() {
  if (logsCard) logsCard.classList.toggle("open");
}

if (logsToggleBtn) logsToggleBtn.addEventListener("click", toggleLogs);
if (actionLogs) actionLogs.addEventListener("click", toggleLogs);

const copyLogsBtn = document.querySelector("#copyLogs");
if (copyLogsBtn) {
  copyLogsBtn.addEventListener("click", () => {
    navigator.clipboard?.writeText(state.logs.join("\n"));
    showToast("Журнал скопирован в буфер");
  });
}

const clearLogsBtn = document.querySelector("#clearLogs");
if (clearLogsBtn) {
  clearLogsBtn.addEventListener("click", () => {
    state.logs = [];
    const terminal = document.querySelector("#logsTerminal");
    if (terminal) terminal.innerHTML = '<p class="log-entry log-accent">[INFO] Журнал очищен</p>';
    showToast("Журнал очищен");
  });
}

// MARK: - Protocol Specs Dialog

const actionProtocol = document.querySelector("#actionProtocol");
const closeProtocolDialog = document.querySelector("#closeProtocolDialog");
const closeProtocolBtn = document.querySelector("#closeProtocolBtn");

if (actionProtocol && protocolDialog) {
  actionProtocol.addEventListener("click", () => protocolDialog.showModal());
}
if (closeProtocolDialog && protocolDialog) {
  closeProtocolDialog.addEventListener("click", () => protocolDialog.close());
}
if (closeProtocolBtn && protocolDialog) {
  closeProtocolBtn.addEventListener("click", () => protocolDialog.close());
}

// MARK: - Add Server Dialog & QR

const selectedServerBtn = document.querySelector("#selectedServer");
if (selectedServerBtn) {
  selectedServerBtn.addEventListener("click", () => navigate("servers"));
}

const quickAddBtn = document.querySelector("#quickAdd");
const addServerBtn = document.querySelector("#addServer");
const closeDialogBtn = document.querySelector("#closeDialog");

if (quickAddBtn && profileDialog) {
  quickAddBtn.addEventListener("click", () => profileDialog.showModal());
}
if (addServerBtn && profileDialog) {
  addServerBtn.addEventListener("click", () => profileDialog.showModal());
}
if (closeDialogBtn && profileDialog) {
  closeDialogBtn.addEventListener("click", () => profileDialog.close());
}

const qrButton = document.querySelector("#qrButton");
const modalQrScan = document.querySelector("#modalQrScan");

function simulateQrScan() {
  if (profileDialog) profileDialog.close();
  showToast("QR-код распознан: Варшава (PL)");
  const newServer = {
    id: `pl-${Date.now()}`,
    code: "PL",
    city: "Варшава",
    endpoint: "pl.obsidian.test:443",
    latency: 38
  };
  state.servers.unshift(newServer);
  state.selectedId = newServer.id;
  renderServers();
  renderSelectedServer();
  addLog(`[OK] Добавлен сервер по QR: ${newServer.city} (${newServer.endpoint})`);
}

if (qrButton) qrButton.addEventListener("click", simulateQrScan);
if (modalQrScan) modalQrScan.addEventListener("click", simulateQrScan);

const modalPasteKey = document.querySelector("#modalPasteKey");
if (modalPasteKey) {
  modalPasteKey.addEventListener("click", () => {
    const keyInput = document.querySelector("#profileKey");
    const nameInput = document.querySelector("#profileName");
    if (keyInput) keyInput.value = "obsidian://de.obsidian.test:443?sni=microsoft.com#Frankfurt-02";
    if (nameInput) nameInput.value = "Frankfurt-02";
    showToast("Ключ вставлен из буфера");
  });
}

const profileForm = document.querySelector("#profileForm");
if (profileForm) {
  profileForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const nameInput = document.querySelector("#profileName");
    const keyInput = document.querySelector("#profileKey");
    const name = (nameInput?.value.trim()) || "Новый сервер";
    const newServer = {
      id: `custom-${Date.now()}`,
      code: "US",
      city: name,
      endpoint: keyInput?.value.trim() || "vpn.obsidian.test:443",
      latency: 74
    };
    state.servers.unshift(newServer);
    state.selectedId = newServer.id;
    renderServers();
    renderSelectedServer();
    addLog(`[OK] Сохранён сервер: ${newServer.city}`);
    showToast(`Сервер сохранён: ${newServer.city}`);
    if (profileDialog) profileDialog.close();
    if (nameInput) nameInput.value = "";
    if (keyInput) keyInput.value = "";
  });
}

// MARK: - Toast

let toastTimer = null;
function showToast(message) {
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.classList.remove("show");
  }, 2200);
}

// Init
renderSelectedServer();
renderServers();
