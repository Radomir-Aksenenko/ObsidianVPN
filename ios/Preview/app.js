const device = document.querySelector(".device");
const screens = [...document.querySelectorAll(".screen")];
const tabs = [...document.querySelectorAll(".tab")];
const dialog = document.querySelector("#profileDialog");
const keyField = document.querySelector("#profileKey");
const toast = document.querySelector("#toast");

const state = {
  connection: "disconnected",
  selectedId: "helsinki",
  connectedAt: null,
  timer: null,
  speedTimer: null,
  servers: [
    { id: "helsinki", code: "FI", city: "Хельсинки", endpoint: "fi.obsidian.test:443", latency: 42 },
    { id: "stockholm", code: "SE", city: "Stockholm-01", endpoint: "91.204.12.44:443", latency: 51, owner: true },
    { id: "frankfurt", code: "DE", city: "Франкфурт", endpoint: "de.obsidian.test:443", latency: 68 }
  ]
};

function navigate(target) {
  screens.forEach((screen) => screen.classList.toggle("active", screen.dataset.screen === target));
  tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.target === target));
}

function selectedServer() {
  return state.servers.find((server) => server.id === state.selectedId) || state.servers[0];
}

function renderSelectedServer() {
  const server = selectedServer();
  document.querySelector("#selectedCode").textContent = server.code;
  document.querySelector("#selectedCity").textContent = server.city;
  document.querySelector("#selectedEndpoint").textContent = server.endpoint;
  document.querySelector("#selectedLatency").textContent = `${server.latency} мс`;
}

function renderServers() {
  const list = document.querySelector("#serverList");
  list.innerHTML = "";
  state.servers.forEach((server) => {
    const button = document.createElement("button");
    button.className = `server-row${server.id === state.selectedId ? " selected" : ""}${server.owner ? " owner" : ""}`;
    button.innerHTML = `
      <span class="country-badge">${server.code}</span>
      <span class="server-row-copy"><strong>${server.city} ${server.owner ? '<span class="owner-tag">СВОЙ VPS</span>' : ""}</strong><small>${server.endpoint}</small></span>
      <span class="latency">${server.latency} мс</span>
      <span class="check">✓</span>`;
    button.addEventListener("click", () => {
      state.selectedId = server.id;
      renderServers();
      renderSelectedServer();
      showToast(`Выбран сервер: ${server.city}`);
      setTimeout(() => navigate("home"), 320);
    });
    list.append(button);
  });
}

function setConnection(next) {
  state.connection = next;
  device.classList.toggle("connecting", next === "connecting");
  device.classList.toggle("connected", next === "connected");

  const title = document.querySelector("#homeTitle");
  const subtitle = document.querySelector("#connectionSubtitle");
  const label = document.querySelector("#connectLabel");
  const button = document.querySelector("#connectButton");

  if (next === "connecting") {
    title.textContent = "Защищаем соединение";
    subtitle.textContent = "Проверяем сервер и создаём туннель";
    label.textContent = "Отмена";
    button.setAttribute("aria-label", "Отменить подключение");
    return;
  }

  if (next === "connected") {
    title.textContent = "Подключено";
    subtitle.textContent = "Трафик защищён протоколом Obsidian";
    label.textContent = "Стоп";
    button.setAttribute("aria-label", "Отключить VPN");
    state.connectedAt = Date.now();
    document.querySelector("#routeMetric").textContent = "TUNNEL";
    startMetrics();
    showToast(`Защищено через ${selectedServer().city}`);
    return;
  }

  title.textContent = "Не подключено";
  subtitle.textContent = "Подключитесь, когда понадобится приватность";
  label.textContent = "Пуск";
  button.setAttribute("aria-label", "Подключить VPN");
  document.querySelector("#routeMetric").textContent = "DIRECT";
  stopMetrics();
}

function toggleConnection() {
  if (state.connection === "connecting") {
    clearTimeout(state.timer);
    setConnection("disconnected");
    showToast("Подключение отменено");
    return;
  }
  if (state.connection === "connected") {
    setConnection("disconnected");
    showToast("VPN отключён");
    return;
  }
  setConnection("connecting");
  state.timer = setTimeout(() => setConnection("connected"), 1350);
}

function startMetrics() {
  stopMetrics(false);
  const started = state.connectedAt;
  const tick = () => {
    const seconds = Math.max(0, Math.floor((Date.now() - started) / 1000));
    const hh = String(Math.floor(seconds / 3600)).padStart(2, "0");
    const mm = String(Math.floor((seconds % 3600) / 60)).padStart(2, "0");
    const ss = String(seconds % 60).padStart(2, "0");
    document.querySelector("#sessionMetric").textContent = `${hh}:${mm}:${ss}`;
  };
  const updateSpeed = () => {
    const value = (3.6 + Math.random() * 18).toFixed(1).replace(".", ",");
    document.querySelector("#speedMetric").textContent = `${value} Мбит/с`;
  };
  tick(); updateSpeed();
  state.timer = setInterval(tick, 1000);
  state.speedTimer = setInterval(updateSpeed, 1800);
}

function stopMetrics(reset = true) {
  clearInterval(state.timer);
  clearInterval(state.speedTimer);
  if (reset) {
    document.querySelector("#sessionMetric").textContent = "—";
    document.querySelector("#speedMetric").textContent = "—";
  }
}

let toastTimer;
function showToast(message) {
  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.classList.add("show");
  toastTimer = setTimeout(() => toast.classList.remove("show"), 2100);
}

function openProfileDialog() {
  keyField.value = "";
  dialog.showModal();
  setTimeout(() => keyField.focus(), 120);
}

tabs.forEach((tab) => tab.addEventListener("click", () => navigate(tab.dataset.target)));
document.querySelector("#connectButton").addEventListener("click", toggleConnection);
document.querySelector("#selectedServer").addEventListener("click", () => navigate("servers"));
document.querySelector("#quickAdd").addEventListener("click", openProfileDialog);
document.querySelector("#addServer").addEventListener("click", openProfileDialog);
document.querySelector("#fillDemo").addEventListener("click", () => {
  keyField.value = "obsidian://public-key@nl.obsidian.test:443?security=reality#Амстердам";
  keyField.focus();
});

document.querySelector("#profileForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const value = keyField.value.trim();
  if (!/^(obsidian:\/\/|vpn:\/\/|OBSDN-)/.test(value)) {
    showToast("Нужен ключ obsidian://, vpn:// или OBSDN-");
    keyField.focus();
    return;
  }
  const hashName = decodeURIComponent(value.split("#")[1] || "Новый сервер");
  const code = hashName.toLowerCase().includes("амстер") ? "NL" : "VPN";
  const server = {
    id: `custom-${Date.now()}`,
    code,
    city: hashName,
    endpoint: value.match(/@([^?#]+)/)?.[1] || "Профиль Obsidian",
    latency: 57
  };
  state.servers.unshift(server);
  state.selectedId = server.id;
  renderServers();
  renderSelectedServer();
  dialog.close();
  navigate("servers");
  showToast("Сервер добавлен");
});

["autoConnect", "killSwitch", "haptics"].forEach((id) => {
  const control = document.querySelector(`#${id}`);
  const saved = localStorage.getItem(`obsidian.${id}`);
  if (saved !== null) control.checked = saved === "true";
  control.addEventListener("change", () => {
    localStorage.setItem(`obsidian.${id}`, String(control.checked));
    showToast("Настройка сохранена");
  });
});

renderServers();
renderSelectedServer();
