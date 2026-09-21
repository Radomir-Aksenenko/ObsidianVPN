const accessState = {
  days: 30,
  devices: 3,
  issued: [
    { id: 1, name: "iPhone Радомира", code: "SE", devices: 1, expires: "бессрочно", active: true },
    { id: 2, name: "Семья", code: "SE", devices: 3, expires: "19 окт", active: true },
    { id: 3, name: "MacBook", code: "SE", devices: 1, expires: "2 дек", active: true }
  ]
};

const issueDialog = document.querySelector("#issueDialog");
const deployDialog = document.querySelector("#deployDialog");
const adminDialog = document.querySelector("#adminDialog");
const keyDialog = document.querySelector("#keyDialog");
let selectedAccessId = null;
let revokeArmed = false;
let resetArmed = false;

function renderAccesses() {
  const list = document.querySelector("#accessList");
  list.innerHTML = accessState.issued.map((key) => `
    <button class="access-row" data-access-id="${key.id}">
      <span class="access-avatar">${key.name.slice(0, 2).toUpperCase()}</span>
      <span><strong>${key.name}</strong><small>${key.code} · ${key.devices} устр. · до ${key.expires}</small></span>
      <i class="access-state"></i><em>›</em>
    </button>`).join("");
  document.querySelector("#accessCount").textContent = accessState.issued.length;
  document.querySelector("#fleetKeys").textContent = accessState.issued.length;
}

function openIssue() {
  document.querySelector("#accessName").value = "Семья";
  issueDialog.showModal();
}

function openAccess(id) {
  const key = accessState.issued.find((item) => item.id === id);
  if (!key) return;
  selectedAccessId = id;
  revokeArmed = false;
  document.querySelector("#revokeAccess").classList.remove("armed");
  document.querySelector("#revokeAccess").textContent = "Отозвать доступ";
  document.querySelector("#keyDetailName").textContent = key.name;
  document.querySelector("#keyDetailAvatar").textContent = key.name.slice(0, 2).toUpperCase();
  document.querySelector("#keyDetailStatus").textContent = key.active ? "Активен" : "Отозван";
  document.querySelector("#keyDetailMeta").textContent = `${key.devices} устр. · до ${key.expires}`;
  document.querySelector("#keyDetailValue").value = `obsidian://${key.code}-${String(key.id).slice(-6)}-9K2M-7F4A`;
  document.querySelector("#qrPanel").hidden = true;
  document.querySelector("#showAccessQr").textContent = "Показать QR";
  keyDialog.showModal();
}

document.querySelectorAll("[data-jump]").forEach((button) => button.addEventListener("click", () => navigate(button.dataset.jump)));
document.querySelector("#issueAccess").addEventListener("click", openIssue);
document.querySelector("#accessList").addEventListener("click", (event) => {
  const row = event.target.closest("[data-access-id]");
  if (row) openAccess(Number(row.dataset.accessId));
});
document.querySelector("#manageVps").addEventListener("click", () => adminDialog.showModal());
document.querySelector("#quickSni").addEventListener("click", () => adminDialog.showModal());
document.querySelector("#quickNetwork").addEventListener("click", () => adminDialog.showModal());
document.querySelector("#quickUpdate").addEventListener("click", () => showToast("Ядро v0.1.0 актуально"));

document.querySelector("#daysChoice").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-days]");
  if (!button) return;
  accessState.days = Number(button.dataset.days);
  document.querySelectorAll("#daysChoice button").forEach((item) => item.classList.toggle("active", item === button));
});
document.querySelector("#devicesMinus").addEventListener("click", () => {
  accessState.devices = Math.max(1, accessState.devices - 1);
  document.querySelector("#devicesCount").textContent = accessState.devices;
});
document.querySelector("#devicesPlus").addEventListener("click", () => {
  accessState.devices = Math.min(20, accessState.devices + 1);
  document.querySelector("#devicesCount").textContent = accessState.devices;
});
document.querySelector("#issueForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const name = document.querySelector("#accessName").value.trim() || "Новый доступ";
  accessState.issued.unshift({ id: Date.now(), name, code: "SE", devices: accessState.devices, expires: accessState.days ? `${accessState.days} дней` : "бессрочно", active: true });
  renderAccesses();
  issueDialog.close();
  showToast(`Ключ «${name}» выпущен`);
});

document.querySelector("#copyAccessKey").addEventListener("click", async () => {
  const value = document.querySelector("#keyDetailValue").value;
  try { await navigator.clipboard.writeText(value); } catch (_) { /* preview may block clipboard */ }
  showToast("Ключ скопирован");
});
document.querySelector("#showAccessQr").addEventListener("click", () => {
  const panel = document.querySelector("#qrPanel");
  panel.hidden = !panel.hidden;
  document.querySelector("#showAccessQr").textContent = panel.hidden ? "Показать QR" : "Скрыть QR";
});
document.querySelector("#revokeAccess").addEventListener("click", (event) => {
  if (!revokeArmed) {
    revokeArmed = true;
    event.currentTarget.classList.add("armed");
    event.currentTarget.textContent = "Подтвердить отзыв";
    showToast("Нажмите ещё раз для подтверждения");
    return;
  }
  accessState.issued = accessState.issued.filter((item) => item.id !== selectedAccessId);
  renderAccesses();
  keyDialog.close();
  showToast("Доступ отозван");
});

function openDeploy() {
  document.querySelector("#deployFields").hidden = false;
  document.querySelector("#deployRunning").hidden = true;
  deployDialog.showModal();
}
document.querySelector("#deployServer").addEventListener("click", openDeploy);
document.querySelector("#deployServerAdmin").addEventListener("click", openDeploy);
document.querySelector("#deployForm").addEventListener("submit", (event) => {
  event.preventDefault();
  document.querySelector("#deployFields").hidden = true;
  document.querySelector("#deployRunning").hidden = false;
  const stages = [
    [18, "Подключение по SSH…", "$ ssh root@203.0.113.42\nUbuntu 24.04 · проверка сети…"],
    [43, "Установка ядра…", "Загрузка obsidian-server\nНастройка systemd и NAT…"],
    [71, "Настройка REALITY…", "Порт 443 открыт\nSNI: www.microsoft.com"],
    [92, "Генерация ключей…", "X25519 + ML-KEM\nЗапуск keyserver…"],
    [100, "Сервер готов", "Проверка туннеля: OK\nStockholm-02 добавлен"]
  ];
  let index = 0;
  const timer = setInterval(() => {
    const [percent, label, log] = stages[index++];
    document.querySelector("#deployPercent").textContent = `${percent}%`;
    document.querySelector("#deployStage").textContent = label;
    document.querySelector("#deployBar").style.width = `${percent}%`;
    document.querySelector("#deployLog").textContent = log;
    if (percent === 100) {
      clearInterval(timer);
      setTimeout(() => { deployDialog.close(); showToast("VPS развёрнут и добавлен"); }, 650);
    }
  }, 520);
});

document.querySelectorAll(".sni-presets button").forEach((button) => button.addEventListener("click", () => {
  document.querySelector("#sniInput").value = button.textContent;
}));
document.querySelector("#applySni").addEventListener("click", () => showToast(`SNI изменён: ${document.querySelector("#sniInput").value}`));
document.querySelector("#ipv6Toggle").addEventListener("change", (event) => {
  document.querySelector("#networkMode").textContent = event.target.checked ? "IPv4 + IPv6" : "IPv4";
  showToast(event.target.checked ? "Dual-Stack включён" : "Чистый IPv4 включён");
});
document.querySelector("#checkUpdate").addEventListener("click", () => showToast("Обновлений нет · v0.1.0"));
document.querySelector("#resetServer").addEventListener("click", (event) => {
  if (!resetArmed) {
    resetArmed = true;
    event.currentTarget.classList.add("armed");
    event.currentTarget.textContent = "Подтвердить обнуление";
    showToast("Нажмите ещё раз · это сбросит ключи в демо");
    return;
  }
  accessState.issued = [{ id: Date.now(), name: "Ключ владельца", code: "SE", devices: 1, expires: "бессрочно", active: true }];
  renderAccesses();
  adminDialog.close();
  resetArmed = false;
  event.currentTarget.classList.remove("armed");
  event.currentTarget.textContent = "Обнулить сервер";
  showToast("Сервер обнулён · новый ключ владельца готов");
});

renderAccesses();
