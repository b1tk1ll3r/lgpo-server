"use strict";

const state = {
  csrf: "",
  version: "dev",
  policies: [],
  profiles: [],
  clients: [],
  route: "dashboard",
  policyFilter: "",
  clientFilter: "",
  clientStatus: "all",
  clientProfile: "all",
  loading: false,
};

const refs = {
  loginView: document.querySelector("#login-view"),
  appView: document.querySelector("#app-view"),
  loginForm: document.querySelector("#login-form"),
  loginError: document.querySelector("#login-error"),
  tokenInput: document.querySelector("#admin-token"),
  toggleToken: document.querySelector("#toggle-token"),
  logout: document.querySelector("#logout-button"),
  pageContent: document.querySelector("#page-content"),
  pageTitle: document.querySelector("#page-title"),
  pageEyebrow: document.querySelector("#page-eyebrow"),
  primaryAction: document.querySelector("#primary-action"),
  refresh: document.querySelector("#refresh-button"),
  lastRefresh: document.querySelector("#last-refresh"),
  serverVersion: document.querySelector("#server-version"),
  navPolicyCount: document.querySelector("#nav-policy-count"),
  navProfileCount: document.querySelector("#nav-profile-count"),
  navClientCount: document.querySelector("#nav-client-count"),
  modalBackdrop: document.querySelector("#modal-backdrop"),
  modal: document.querySelector("#modal"),
  modalTitle: document.querySelector("#modal-title"),
  modalEyebrow: document.querySelector("#modal-eyebrow"),
  modalContent: document.querySelector("#modal-content"),
  modalClose: document.querySelector("#modal-close"),
  confirmBackdrop: document.querySelector("#confirm-backdrop"),
  confirmTitle: document.querySelector("#confirm-title"),
  confirmMessage: document.querySelector("#confirm-message"),
  confirmSubmit: document.querySelector("#confirm-submit"),
  confirmCancel: document.querySelector("#confirm-cancel"),
  toastRegion: document.querySelector("#toast-region"),
};

const routeMeta = {
  dashboard: { title: "Übersicht", eyebrow: "Verwaltung", action: "" },
  policies: { title: "Richtlinien", eyebrow: "Policy Repository", action: "Richtlinie hochladen" },
  profiles: { title: "Profile", eyebrow: "Zuweisungen", action: "Profil erstellen" },
  clients: { title: "Clients", eyebrow: "Agent-Status", action: "" },
};

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function encoded(value) {
  return encodeURIComponent(String(value));
}

function decoded(value) {
  return decodeURIComponent(String(value));
}

function formatDate(value, withSeconds = false) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("de-DE", {
    dateStyle: "medium",
    timeStyle: withSeconds ? "medium" : "short",
  }).format(date);
}

function relativeDate(value) {
  if (!value) return "nie";
  const date = new Date(value);
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const abs = Math.abs(seconds);
  const formatter = new Intl.RelativeTimeFormat("de-DE", { numeric: "auto" });
  if (abs < 60) return formatter.format(seconds, "second");
  if (abs < 3600) return formatter.format(Math.round(seconds / 60), "minute");
  if (abs < 86400) return formatter.format(Math.round(seconds / 3600), "hour");
  return formatter.format(Math.round(seconds / 86400), "day");
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (value < 1024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let size = value;
  let unit = -1;
  do {
    size /= 1024;
    unit += 1;
  } while (size >= 1024 && unit < units.length - 1);
  return `${size.toLocaleString("de-DE", { maximumFractionDigits: size >= 10 ? 1 : 2 })} ${units[unit]}`;
}

function shortHash(value, length = 12) {
  if (!value) return "—";
  return `${String(value).slice(0, length)}…`;
}

function isStale(client) {
  if (!client.reported_at) return true;
  return Date.now() - new Date(client.reported_at).getTime() > 24 * 60 * 60 * 1000;
}

async function request(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers || {});
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && state.csrf) {
    headers.set("X-CSRF-Token", state.csrf);
  }
  if (options.json !== undefined) {
    headers.set("Content-Type", "application/json");
    options.body = JSON.stringify(options.json);
    delete options.json;
  }
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    method,
    headers,
  });
  if (response.status === 401) {
    showLogin();
    throw new Error("Die Sitzung ist abgelaufen. Bitte erneut anmelden.");
  }
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const body = await response.json();
      message = body.error || message;
    } catch (_) {
      // Keep the HTTP status as fallback.
    }
    throw new Error(message);
  }
  if (response.status === 204) return null;
  const type = response.headers.get("Content-Type") || "";
  return type.includes("application/json") ? response.json() : response;
}

async function bootstrap() {
  bindStaticEvents();
  try {
    const session = await request("/ui/api/session");
    state.csrf = session.csrf_token;
    state.version = session.version || "dev";
    showApp();
    await loadAll();
  } catch (_) {
    showLogin();
  }
}

function bindStaticEvents() {
  refs.loginForm.addEventListener("submit", login);
  refs.toggleToken.addEventListener("click", () => {
    const visible = refs.tokenInput.type === "text";
    refs.tokenInput.type = visible ? "password" : "text";
    refs.toggleToken.textContent = visible ? "Anzeigen" : "Verbergen";
  });
  refs.logout.addEventListener("click", logout);
  refs.refresh.addEventListener("click", () => loadAll(true));
  refs.primaryAction.addEventListener("click", () => {
    if (state.route === "policies") openUploadDialog();
    if (state.route === "profiles") openProfileEditor(null);
  });
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.addEventListener("click", () => navigate(button.dataset.route));
  });
  refs.pageContent.addEventListener("click", handlePageClick);
  refs.pageContent.addEventListener("input", handlePageInput);
  refs.pageContent.addEventListener("change", handlePageInput);
  refs.modalClose.addEventListener("click", closeModal);
  refs.modalBackdrop.addEventListener("click", (event) => {
    if (event.target === refs.modalBackdrop) closeModal();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !refs.modalBackdrop.classList.contains("hidden")) closeModal();
  });
  window.addEventListener("hashchange", () => {
    const route = location.hash.replace(/^#\/?/, "");
    if (routeMeta[route]) setRoute(route, false);
  });
}

async function login(event) {
  event.preventDefault();
  refs.loginError.textContent = "";
  const submit = refs.loginForm.querySelector("button[type='submit']");
  submit.disabled = true;
  submit.textContent = "Anmeldung läuft …";
  try {
    const session = await request("/ui/api/session", {
      method: "POST",
      json: { token: refs.tokenInput.value },
    });
    state.csrf = session.csrf_token;
    state.version = session.version || "dev";
    refs.tokenInput.value = "";
    showApp();
    await loadAll();
  } catch (error) {
    refs.loginError.textContent = error.message === "invalid credentials" ? "Das Admin-Token ist ungültig." : error.message;
  } finally {
    submit.disabled = false;
    submit.textContent = "Anmelden";
  }
}

async function logout() {
  try {
    await request("/ui/api/session", { method: "DELETE" });
  } catch (_) {
    // A local logout is still useful if the server session is already invalid.
  }
  state.csrf = "";
  state.policies = [];
  state.profiles = [];
  state.clients = [];
  showLogin();
}

function showLogin() {
  refs.appView.classList.add("hidden");
  refs.loginView.classList.remove("hidden");
  refs.loginError.textContent = "";
  setTimeout(() => refs.tokenInput.focus(), 0);
}

function showApp() {
  refs.loginView.classList.add("hidden");
  refs.appView.classList.remove("hidden");
  refs.serverVersion.textContent = `Backend ${state.version}`;
  const hashRoute = location.hash.replace(/^#\/?/, "");
  setRoute(routeMeta[hashRoute] ? hashRoute : "dashboard", false);
}

async function loadAll(notify = false) {
  if (state.loading) return;
  state.loading = true;
  refs.refresh.disabled = true;
  refs.refresh.textContent = "Lädt …";
  if (!state.policies.length && !state.profiles.length && !state.clients.length) {
    refs.pageContent.innerHTML = loadingMarkup("Verwaltungsdaten werden geladen …");
  }
  try {
    const [policies, profiles, clients] = await Promise.all([
      request("/api/v1/admin/policies"),
      request("/api/v1/admin/profiles"),
      request("/api/v1/admin/clients"),
    ]);
    state.policies = policies || [];
    state.profiles = profiles || [];
    state.clients = clients || [];
    updateCounts();
    renderRoute();
    refs.lastRefresh.textContent = `Stand ${new Intl.DateTimeFormat("de-DE", { timeStyle: "short" }).format(new Date())}`;
    if (notify) toast("success", "Aktualisiert", "Die Verwaltungsdaten sind auf dem neuesten Stand.");
  } catch (error) {
    refs.pageContent.innerHTML = errorState(error.message);
    if (notify) toast("error", "Aktualisierung fehlgeschlagen", error.message);
  } finally {
    state.loading = false;
    refs.refresh.disabled = false;
    refs.refresh.textContent = "Aktualisieren";
  }
}

function updateCounts() {
  refs.navPolicyCount.textContent = state.policies.length;
  refs.navProfileCount.textContent = state.profiles.length;
  refs.navClientCount.textContent = state.clients.length;
}

function navigate(route) {
  if (!routeMeta[route]) return;
  location.hash = route;
  setRoute(route, false);
}

function setRoute(route, updateHash = true) {
  state.route = route;
  if (updateHash) location.hash = route;
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.classList.toggle("active", button.dataset.route === route);
  });
  const meta = routeMeta[route];
  refs.pageTitle.textContent = meta.title;
  refs.pageEyebrow.textContent = meta.eyebrow;
  refs.primaryAction.textContent = meta.action;
  refs.primaryAction.classList.toggle("hidden", !meta.action);
  renderRoute();
  refs.pageContent.focus({ preventScroll: true });
}

function renderRoute() {
  if (refs.appView.classList.contains("hidden")) return;
  if (state.route === "dashboard") renderDashboard();
  if (state.route === "policies") renderPolicies();
  if (state.route === "profiles") renderProfiles();
  if (state.route === "clients") renderClients();
}

function renderDashboard() {
  const versions = state.policies.reduce((sum, policy) => sum + policy.versions.length, 0);
  const healthy = state.clients.filter((client) => client.success && !isStale(client)).length;
  const failed = state.clients.filter((client) => !client.success && !isStale(client)).length;
  const stale = state.clients.filter(isStale).length;
  const healthPercent = state.clients.length ? Math.round((healthy / state.clients.length) * 100) : 0;
  const recentVersions = state.policies
    .flatMap((policy) => policy.versions.map((version) => ({ ...version, policy: policy.name })))
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 7);
  const recentClients = [...state.clients]
    .sort((a, b) => new Date(b.reported_at) - new Date(a.reported_at))
    .slice(0, 6);

  refs.pageContent.innerHTML = `
    <section class="stats-grid" aria-label="Kennzahlen">
      ${statCard("Richtlinienobjekte", state.policies.length, `${versions} unveränderliche Versionen`)}
      ${statCard("Profile", state.profiles.length, "Geordnete Richtliniensätze")}
      ${statCard("Gemeldete Clients", state.clients.length, `${healthy} aktuell erfolgreich`)}
      ${statCard("Handlungsbedarf", failed + stale, `${failed} Fehler · ${stale} länger als 24 h still`)}
    </section>
    <section class="dashboard-grid">
      <div class="panel">
        <header class="panel-header"><h2>Letzte Richtlinienversionen</h2><button class="button ghost small" data-action="go-policies">Alle anzeigen</button></header>
        <div class="panel-body table-wrap">
          ${recentVersions.length ? `
            <table class="data-table">
              <thead><tr><th>Richtlinie</th><th>Version</th><th>Zeitpunkt</th><th>Größe</th></tr></thead>
              <tbody>${recentVersions.map((version) => `
                <tr>
                  <td><strong>${escapeHTML(version.policy)}</strong></td>
                  <td class="mono">${escapeHTML(version.version)}</td>
                  <td title="${escapeHTML(formatDate(version.created_at, true))}">${escapeHTML(relativeDate(version.created_at))}</td>
                  <td>${formatBytes(version.size)}</td>
                </tr>`).join("")}</tbody>
            </table>` : emptyInline("Noch keine Richtlinienversion vorhanden.")}
        </div>
      </div>
      <div class="panel">
        <header class="panel-header"><h2>Client-Gesundheit</h2><button class="button ghost small" data-action="go-clients">Details</button></header>
        <div class="health-ring">
          <div class="ring-chart">
            <svg class="ring-svg" viewBox="0 0 42 42" aria-hidden="true">
              <circle class="ring-track" cx="21" cy="21" r="15.9155"></circle>
              <circle class="ring-progress" cx="21" cy="21" r="15.9155" pathLength="100" stroke-dasharray="${healthPercent} 100"></circle>
            </svg>
            <div class="ring-center"><span class="ring-value">${healthPercent}%</span><span class="ring-label">aktuell erfolgreich</span></div>
          </div>
          <div class="health-legend">
            <div class="legend-row"><span><span class="badge success">Erfolgreich</span></span><strong>${healthy}</strong></div>
            <div class="legend-row"><span><span class="badge error">Fehler</span></span><strong>${failed}</strong></div>
            <div class="legend-row"><span><span class="badge warning">Veraltet</span></span><strong>${stale}</strong></div>
          </div>
        </div>
      </div>
    </section>
    <section class="panel panel-spaced">
      <header class="panel-header"><h2>Zuletzt gemeldete Clients</h2></header>
      <div class="panel-body table-wrap">
        ${recentClients.length ? clientTable(recentClients, false) : emptyInline("Noch kein Agent hat einen Status gemeldet.")}
      </div>
    </section>`;
}

function statCard(label, value, detail) {
  return `<article class="stat-card"><span class="stat-label">${escapeHTML(label)}</span><strong class="stat-value">${escapeHTML(value)}</strong><span class="stat-detail">${escapeHTML(detail)}</span></article>`;
}

function renderPolicies() {
  refs.pageContent.innerHTML = `
    <div class="toolbar">
      <div class="search-wrap"><input id="policy-search" type="search" placeholder="Richtlinien durchsuchen" value="${escapeHTML(state.policyFilter)}" aria-label="Richtlinien durchsuchen"></div>
      <div class="toolbar-group"><span class="muted small-text">${state.policies.length} Objekte</span></div>
    </div>
    <div id="policy-list">${policyCards()}</div>`;
}

function policyCards() {
  const query = state.policyFilter.trim().toLowerCase();
  const policies = state.policies.filter((policy) => policy.name.toLowerCase().includes(query));
  if (!policies.length) {
    return state.policies.length
      ? emptyState("⌕", "Keine Richtlinie gefunden", "Passe den Suchbegriff an.", "")
      : emptyState("▤", "Noch keine Richtlinie", "Lade die erste Microsoft-GPO-Sicherung als ZIP hoch.", `<button class="button primary" data-action="upload-policy">Richtlinie hochladen</button>`);
  }
  return `<div class="policy-list">${policies.map((policy) => {
    const versions = [...policy.versions].reverse();
    const latest = versions[0];
    return `<article class="policy-card">
      <div class="policy-summary">
        <div>
          <div class="policy-title-row"><h2>${escapeHTML(policy.name)}</h2><span class="badge blue">${policy.versions.length} Version${policy.versions.length === 1 ? "" : "en"}</span></div>
          <div class="policy-meta">
            <span>Aktuell: <span class="mono">${escapeHTML(latest?.version || "—")}</span></span>
            <span>Geändert: ${escapeHTML(relativeDate(latest?.created_at))}</span>
            <span>${formatBytes(latest?.size || 0)}</span>
          </div>
        </div>
        <div class="policy-actions">
          <button class="button secondary small" data-action="upload-to-policy" data-policy="${encoded(policy.name)}">Neue Version</button>
          <button class="button danger-soft small" data-action="delete-policy" data-policy="${encoded(policy.name)}">Löschen</button>
        </div>
      </div>
      <div class="version-list">
        ${versions.map((version, index) => `
          <div class="version-row">
            <div>
              <div class="version-id mono">${escapeHTML(version.version)} ${index === 0 ? '<span class="badge success">latest</span>' : ""}</div>
              <div class="small-text muted" title="${escapeHTML(formatDate(version.created_at, true))}">${escapeHTML(formatDate(version.created_at))}</div>
            </div>
            <div class="version-note">${version.note ? escapeHTML(version.note) : '<span class="muted">Keine Notiz</span>'}</div>
            <div>
              <div class="hash-line"><span>Semantik</span><span class="mono truncate" title="${escapeHTML(version.semantic_sha256)}">${escapeHTML(shortHash(version.semantic_sha256, 18))}</span><button class="icon-button" data-action="copy" data-copy="${escapeHTML(version.semantic_sha256)}">Kopieren</button></div>
              <div class="hash-line"><span>${version.policy_file_count} Policy-Dateien · ${version.file_count} gesamt · ${formatBytes(version.size)}</span></div>
            </div>
            <div class="row-buttons">
              <button class="button secondary small" data-action="download-version" data-policy="${encoded(policy.name)}" data-version="${encoded(version.version)}">ZIP</button>
              <button class="button danger-soft small" data-action="delete-version" data-policy="${encoded(policy.name)}" data-version="${encoded(version.version)}" ${policy.versions.length === 1 ? "disabled title=\"Letzte Version: Richtlinie vollständig löschen\"" : ""}>Löschen</button>
            </div>
          </div>`).join("")}
      </div>
    </article>`;
  }).join("")}</div>`;
}

function renderProfiles() {
  if (!state.profiles.length) {
    refs.pageContent.innerHTML = emptyState("◫", "Noch kein Profil", "Ein Profil definiert die Reihenfolge und Versionen, die ein Client anwenden soll.", `<button class="button primary" data-action="create-profile" ${state.policies.length ? "" : "disabled"}>Profil erstellen</button>`);
    return;
  }
  refs.pageContent.innerHTML = `
    <div class="section-heading"><div><h2>Richtlinienzuweisungen</h2><p>Die Reihenfolge bestimmt, in welcher Reihenfolge LGPO die Sicherungen importiert.</p></div></div>
    <div class="profile-grid">${state.profiles.map((profile) => `
      <article class="profile-card">
        <div class="profile-card-header">
          <div><h2>${escapeHTML(profile.name)}</h2><div class="small-text muted">Aktualisiert ${escapeHTML(relativeDate(profile.updated_at))}</div></div>
          <span class="badge neutral">${profile.policies.length} Richtlinien</span>
        </div>
        <div class="policy-stack">${profile.policies.map((ref, index) => `
          <div class="policy-stack-item"><span class="order-number">${index + 1}</span><strong>${escapeHTML(ref.policy)}</strong><span class="badge ${ref.version === "latest" ? "blue" : "neutral"}">${escapeHTML(ref.version)}</span></div>`).join("")}</div>
        <footer class="profile-card-footer">
          <span class="small-text muted">${escapeHTML(formatDate(profile.updated_at))}</span>
          <div class="toolbar-group">
            <button class="button secondary small" data-action="edit-profile" data-profile="${encoded(profile.name)}">Bearbeiten</button>
            <button class="button danger-soft small" data-action="delete-profile" data-profile="${encoded(profile.name)}">Löschen</button>
          </div>
        </footer>
      </article>`).join("")}</div>`;
}

function renderClients() {
  const profiles = [...new Set(state.clients.map((client) => client.profile).filter(Boolean))].sort();
  const visible = filteredClients();
  refs.pageContent.innerHTML = `
    <div class="toolbar">
      <div class="toolbar-group">
        <div class="search-wrap"><input id="client-search" type="search" placeholder="Client, Hostname oder Meldung" value="${escapeHTML(state.clientFilter)}" aria-label="Clients durchsuchen"></div>
        <select id="client-status" class="filter-select" aria-label="Status filtern">
          <option value="all" ${state.clientStatus === "all" ? "selected" : ""}>Alle Status</option>
          <option value="success" ${state.clientStatus === "success" ? "selected" : ""}>Erfolgreich</option>
          <option value="error" ${state.clientStatus === "error" ? "selected" : ""}>Fehler</option>
          <option value="stale" ${state.clientStatus === "stale" ? "selected" : ""}>Veraltet</option>
        </select>
        <select id="client-profile" class="filter-select" aria-label="Profil filtern">
          <option value="all">Alle Profile</option>
          ${profiles.map((profile) => `<option value="${escapeHTML(profile)}" ${state.clientProfile === profile ? "selected" : ""}>${escapeHTML(profile)}</option>`).join("")}
        </select>
      </div>
      <span class="muted small-text">${visible.length} von ${state.clients.length}</span>
    </div>
    <section class="panel">
      <div id="client-table" class="panel-body table-wrap">${visible.length ? clientTable(visible, true) : emptyInline("Keine Clients entsprechen dem Filter.")}</div>
    </section>`;
}

function filteredClients() {
  const query = state.clientFilter.trim().toLowerCase();
  return state.clients.filter((client) => {
    const haystack = [client.client_id, client.hostname, client.profile, client.message, client.operating_system].join(" ").toLowerCase();
    if (query && !haystack.includes(query)) return false;
    if (state.clientProfile !== "all" && client.profile !== state.clientProfile) return false;
    if (state.clientStatus === "stale" && !isStale(client)) return false;
    if (state.clientStatus === "success" && (!client.success || isStale(client))) return false;
    if (state.clientStatus === "error" && (client.success || isStale(client))) return false;
    return true;
  });
}

function clientTable(clients, includeActions) {
  return `<table class="data-table">
    <thead><tr><th>Client</th><th>Status</th><th>Profil</th><th>Generation</th><th>Letzte Meldung</th><th>System</th>${includeActions ? "<th></th>" : ""}</tr></thead>
    <tbody>${clients.map((client) => {
      const stale = isStale(client);
      const status = stale ? '<span class="badge warning">Veraltet</span>' : client.success ? '<span class="badge success">Erfolgreich</span>' : '<span class="badge error">Fehler</span>';
      return `<tr class="${stale ? "client-stale" : ""}">
        <td><div class="client-name">${escapeHTML(client.hostname || client.client_id)}</div><div class="client-id mono">${escapeHTML(client.client_id)}</div>${client.message ? `<div class="client-message small-text muted" title="${escapeHTML(client.message)}">${escapeHTML(client.message)}</div>` : ""}</td>
        <td>${status}</td>
        <td><span class="badge neutral">${escapeHTML(client.profile || "—")}</span></td>
        <td class="mono" title="${escapeHTML(client.generation || "")}">${escapeHTML(shortHash(client.generation, 10))}</td>
        <td title="${escapeHTML(formatDate(client.reported_at, true))}">${escapeHTML(relativeDate(client.reported_at))}</td>
        <td><div>${escapeHTML(client.operating_system || "—")}</div><div class="small-text muted">Agent ${escapeHTML(client.agent_version || "—")}</div></td>
        ${includeActions ? `<td class="actions"><button class="button danger-soft small" data-action="delete-client" data-client="${encoded(client.client_id)}">Entfernen</button></td>` : ""}
      </tr>`;
    }).join("")}</tbody>
  </table>`;
}

function handlePageInput(event) {
  if (event.target.id === "policy-search") {
    state.policyFilter = event.target.value;
    const list = document.querySelector("#policy-list");
    if (list) list.innerHTML = policyCards();
  }
  if (event.target.id === "client-search") state.clientFilter = event.target.value;
  if (event.target.id === "client-status") state.clientStatus = event.target.value;
  if (event.target.id === "client-profile") state.clientProfile = event.target.value;
  if (["client-search", "client-status", "client-profile"].includes(event.target.id)) {
    const table = document.querySelector("#client-table");
    const visible = filteredClients();
    if (table) table.innerHTML = visible.length ? clientTable(visible, true) : emptyInline("Keine Clients entsprechen dem Filter.");
  }
}

async function handlePageClick(event) {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  const action = button.dataset.action;
  if (action === "retry") await loadAll(true);
  if (action === "go-policies") navigate("policies");
  if (action === "go-clients") navigate("clients");
  if (action === "upload-policy" || action === "create-profile") {
    action === "upload-policy" ? openUploadDialog() : openProfileEditor(null);
  }
  if (action === "upload-to-policy") openUploadDialog(decoded(button.dataset.policy));
  if (action === "edit-profile") openProfileEditor(state.profiles.find((profile) => profile.name === decoded(button.dataset.profile)));
  if (action === "delete-policy") await deletePolicy(decoded(button.dataset.policy));
  if (action === "delete-version") await deleteVersion(decoded(button.dataset.policy), decoded(button.dataset.version));
  if (action === "download-version") await downloadVersion(decoded(button.dataset.policy), decoded(button.dataset.version), button);
  if (action === "delete-profile") await deleteProfile(decoded(button.dataset.profile));
  if (action === "delete-client") await deleteClient(decoded(button.dataset.client));
  if (action === "copy") await copyText(button.dataset.copy || "");
}

function openUploadDialog(fixedPolicy = "") {
  openModal("Policy Repository", fixedPolicy ? "Neue Richtlinienversion" : "Richtlinie hochladen", `
    <form id="upload-form">
      <div class="form-grid">
        <div class="field-group">
          <label for="upload-policy-name">Richtlinienname</label>
          <input id="upload-policy-name" name="policy" pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,63}" maxlength="64" value="${escapeHTML(fixedPolicy)}" ${fixedPolicy ? "disabled" : ""} required>
          <p class="field-help">Buchstaben, Zahlen, Punkt, Unterstrich und Bindestrich.</p>
        </div>
        <div class="field-group">
          <label for="upload-file">Microsoft-GPO-Sicherung</label>
          <input id="upload-file" name="bundle" type="file" accept=".zip,application/zip" required>
          <p class="field-help">ZIP mit backup.xml und DomainSysvol/GPO.</p>
        </div>
        <div class="field-group full">
          <label for="upload-note">Änderungsnotiz</label>
          <textarea id="upload-note" name="note" maxlength="4096" placeholder="Zum Beispiel Change-ID und kurze Beschreibung"></textarea>
        </div>
        <div class="checkbox-row full">
          <input id="upload-force" name="force" type="checkbox">
          <label for="upload-force">Neue Version auch bei identischem semantischem Hash erzwingen</label>
        </div>
      </div>
      <p id="upload-error" class="form-error" role="alert"></p>
      <div id="upload-progress" class="upload-progress hidden"><div class="upload-progress-bar"></div></div>
      <div class="dialog-actions"><button class="button secondary" type="button" data-modal-close>Abbrechen</button><button class="button primary" type="submit">Prüfen und hochladen</button></div>
    </form>`);
  refs.modalContent.querySelector("[data-modal-close]").addEventListener("click", closeModal);
  refs.modalContent.querySelector("#upload-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const error = form.querySelector("#upload-error");
    const submit = form.querySelector("button[type='submit']");
    const progress = form.querySelector("#upload-progress");
    error.textContent = "";
    submit.disabled = true;
    submit.textContent = "Upload läuft …";
    progress.classList.remove("hidden");
    const policy = fixedPolicy || form.elements.policy.value.trim();
    const data = new FormData();
    data.append("bundle", form.elements.bundle.files[0]);
    data.append("note", form.elements.note.value);
    data.append("force", form.elements.force.checked ? "true" : "false");
    try {
      const result = await request(`/api/v1/admin/policies/${encodeURIComponent(policy)}/versions`, { method: "POST", body: data });
      closeModal();
      await loadAll();
      navigate("policies");
      toast("success", result.created ? "Version angelegt" : "Keine Änderung erkannt", result.created ? `${policy} · ${result.version.version}` : `Der semantische Inhalt entspricht bereits ${result.version.version}.`);
    } catch (uploadError) {
      error.textContent = uploadError.message;
    } finally {
      submit.disabled = false;
      submit.textContent = "Prüfen und hochladen";
      progress.classList.add("hidden");
    }
  });
}

function openProfileEditor(profile) {
  if (!state.policies.length) {
    toast("error", "Keine Richtlinien vorhanden", "Lade zuerst mindestens eine Richtlinie hoch.");
    return;
  }
  const editing = Boolean(profile);
  let rows = profile ? profile.policies.map((item) => ({ ...item })) : [{ policy: state.policies[0].name, version: "latest" }];
  openModal("Zuweisungen", editing ? "Profil bearbeiten" : "Profil erstellen", `
    <form id="profile-form">
      <div class="field-group">
        <label for="profile-name">Profilname</label>
        <input id="profile-name" name="name" pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,63}" maxlength="64" value="${escapeHTML(profile?.name || "")}" ${editing ? "disabled" : ""} required>
      </div>
      <div class="section-heading compact"><div><h2>Reihenfolge</h2><p>Später importierte Richtlinien können frühere Einstellungen überschreiben.</p></div><button id="add-profile-row" class="button secondary small" type="button">Richtlinie hinzufügen</button></div>
      <div id="profile-rows" class="profile-editor-rows"></div>
      <p id="profile-error" class="form-error" role="alert"></p>
      <div class="dialog-actions"><button class="button secondary" type="button" data-modal-close>Abbrechen</button><button class="button primary" type="submit">Profil speichern</button></div>
    </form>`, true);

  const rowsElement = refs.modalContent.querySelector("#profile-rows");
  const renderRows = () => {
    rowsElement.innerHTML = rows.map((row, index) => {
      const policy = state.policies.find((item) => item.name === row.policy) || state.policies[0];
      if (!policy) return "";
      const versions = [...policy.versions].reverse();
      const validVersion = row.version === "latest" || versions.some((version) => version.version === row.version) ? row.version : "latest";
      row.policy = policy.name;
      row.version = validVersion;
      return `<div class="profile-editor-row" data-row="${index}">
        <span class="drag-number">${index + 1}</span>
        <select data-field="policy" aria-label="Richtlinie ${index + 1}">${state.policies.map((item) => `<option value="${escapeHTML(item.name)}" ${item.name === row.policy ? "selected" : ""}>${escapeHTML(item.name)}</option>`).join("")}</select>
        <select data-field="version" aria-label="Version ${index + 1}"><option value="latest" ${row.version === "latest" ? "selected" : ""}>latest – immer aktuell</option>${versions.map((version) => `<option value="${escapeHTML(version.version)}" ${version.version === row.version ? "selected" : ""}>${escapeHTML(version.version)}</option>`).join("")}</select>
        <div class="row-buttons">
          <button class="icon-button" type="button" data-row-action="up" title="Nach oben" ${index === 0 ? "disabled" : ""}>↑</button>
          <button class="icon-button" type="button" data-row-action="down" title="Nach unten" ${index === rows.length - 1 ? "disabled" : ""}>↓</button>
          <button class="icon-button" type="button" data-row-action="remove" title="Entfernen" ${rows.length === 1 ? "disabled" : ""}>×</button>
        </div>
      </div>`;
    }).join("");
  };
  renderRows();

  refs.modalContent.querySelector("[data-modal-close]").addEventListener("click", closeModal);
  refs.modalContent.querySelector("#add-profile-row").addEventListener("click", () => {
    const used = new Set(rows.map((row) => row.policy));
    const next = state.policies.find((policy) => !used.has(policy.name));
    if (!next) {
      toast("error", "Keine weitere Richtlinie", "Jede Richtlinie darf pro Profil nur einmal vorkommen.");
      return;
    }
    rows.push({ policy: next.name, version: "latest" });
    renderRows();
  });
  rowsElement.addEventListener("change", (event) => {
    const rowElement = event.target.closest("[data-row]");
    if (!rowElement) return;
    const index = Number(rowElement.dataset.row);
    if (event.target.dataset.field === "policy") {
      rows[index] = { policy: event.target.value, version: "latest" };
      renderRows();
    }
    if (event.target.dataset.field === "version") rows[index].version = event.target.value;
  });
  rowsElement.addEventListener("click", (event) => {
    const button = event.target.closest("[data-row-action]");
    if (!button) return;
    const index = Number(button.closest("[data-row]").dataset.row);
    if (button.dataset.rowAction === "up" && index > 0) [rows[index - 1], rows[index]] = [rows[index], rows[index - 1]];
    if (button.dataset.rowAction === "down" && index < rows.length - 1) [rows[index + 1], rows[index]] = [rows[index], rows[index + 1]];
    if (button.dataset.rowAction === "remove" && rows.length > 1) rows.splice(index, 1);
    renderRows();
  });
  refs.modalContent.querySelector("#profile-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const error = form.querySelector("#profile-error");
    const submit = form.querySelector("button[type='submit']");
    const name = profile?.name || form.elements.name.value.trim();
    const unique = new Set(rows.map((row) => row.policy));
    if (unique.size !== rows.length) {
      error.textContent = "Eine Richtlinie darf im Profil nur einmal vorkommen.";
      return;
    }
    error.textContent = "";
    submit.disabled = true;
    submit.textContent = "Speichert …";
    try {
      await request(`/api/v1/admin/profiles/${encodeURIComponent(name)}`, { method: "PUT", json: { policies: rows } });
      closeModal();
      await loadAll();
      navigate("profiles");
      toast("success", editing ? "Profil aktualisiert" : "Profil erstellt", `${name} enthält ${rows.length} Richtlinien.`);
    } catch (saveError) {
      error.textContent = saveError.message;
    } finally {
      submit.disabled = false;
      submit.textContent = "Profil speichern";
    }
  });
}

async function deletePolicy(name) {
  const ok = await confirmAction("Richtlinie löschen", `Alle Versionen und ZIP-Artefakte von „${name}“ werden dauerhaft gelöscht. Profile, die diese Richtlinie verwenden, müssen vorher angepasst werden.`, "Richtlinie löschen");
  if (!ok) return;
  try {
    await request(`/api/v1/admin/policies/${encodeURIComponent(name)}`, { method: "DELETE" });
    await loadAll();
    toast("success", "Richtlinie gelöscht", name);
  } catch (error) {
    toast("error", "Löschen nicht möglich", error.message);
  }
}

async function deleteVersion(policy, version) {
  const ok = await confirmAction("Version löschen", `Die unveränderliche Version „${version}“ von „${policy}“ wird einschließlich ZIP-Artefakt gelöscht. Fest angeheftete Profilversionen müssen vorher geändert werden.`, "Version löschen");
  if (!ok) return;
  try {
    await request(`/api/v1/admin/policies/${encodeURIComponent(policy)}/versions/${encodeURIComponent(version)}`, { method: "DELETE" });
    await loadAll();
    toast("success", "Version gelöscht", version);
  } catch (error) {
    toast("error", "Löschen nicht möglich", error.message);
  }
}

async function deleteProfile(name) {
  const ok = await confirmAction("Profil löschen", `Das Profil „${name}“ wird dauerhaft entfernt. Bereits konfigurierte Agents erhalten danach für dieses Profil HTTP 404.`, "Profil löschen");
  if (!ok) return;
  try {
    await request(`/api/v1/admin/profiles/${encodeURIComponent(name)}`, { method: "DELETE" });
    await loadAll();
    toast("success", "Profil gelöscht", name);
  } catch (error) {
    toast("error", "Löschen nicht möglich", error.message);
  }
}

async function deleteClient(clientID) {
  const ok = await confirmAction("Client-Eintrag entfernen", `Der zuletzt gespeicherte Status von „${clientID}“ wird entfernt. Der Agent erscheint bei seiner nächsten Meldung automatisch wieder.`, "Eintrag entfernen");
  if (!ok) return;
  try {
    await request(`/api/v1/admin/clients/${encodeURIComponent(clientID)}`, { method: "DELETE" });
    await loadAll();
    toast("success", "Client-Eintrag entfernt", clientID);
  } catch (error) {
    toast("error", "Entfernen nicht möglich", error.message);
  }
}

async function downloadVersion(policy, version, button) {
  const old = button.textContent;
  button.disabled = true;
  button.textContent = "Lädt …";
  try {
    const response = await request(`/api/v1/admin/policies/${encodeURIComponent(policy)}/versions/${encodeURIComponent(version)}/artifact`);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${policy}-${version}.zip`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    toast("error", "ZIP konnte nicht geladen werden", error.message);
  } finally {
    button.disabled = false;
    button.textContent = old;
  }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("success", "Kopiert", "Der Hash wurde in die Zwischenablage kopiert.");
  } catch (_) {
    toast("error", "Kopieren fehlgeschlagen", "Die Zwischenablage ist für diese Seite nicht verfügbar.");
  }
}

function openModal(eyebrow, title, content, wide = false) {
  refs.modalEyebrow.textContent = eyebrow;
  refs.modalTitle.textContent = title;
  refs.modalContent.innerHTML = content;
  refs.modal.classList.toggle("wide-modal", wide);
  refs.modalBackdrop.classList.remove("hidden");
  document.body.style.overflow = "hidden";
  setTimeout(() => refs.modalContent.querySelector("input, select, textarea, button")?.focus(), 0);
}

function closeModal() {
  refs.modalBackdrop.classList.add("hidden");
  refs.modal.classList.remove("wide-modal");
  refs.modalContent.innerHTML = "";
  document.body.style.overflow = "";
}

function confirmAction(title, message, submitLabel) {
  refs.confirmTitle.textContent = title;
  refs.confirmMessage.textContent = message;
  refs.confirmSubmit.textContent = submitLabel;
  refs.confirmBackdrop.classList.remove("hidden");
  return new Promise((resolve) => {
    const finish = (value) => {
      refs.confirmBackdrop.classList.add("hidden");
      refs.confirmSubmit.removeEventListener("click", accept);
      refs.confirmCancel.removeEventListener("click", cancel);
      refs.confirmBackdrop.removeEventListener("click", backdrop);
      resolve(value);
    };
    const accept = () => finish(true);
    const cancel = () => finish(false);
    const backdrop = (event) => { if (event.target === refs.confirmBackdrop) finish(false); };
    refs.confirmSubmit.addEventListener("click", accept);
    refs.confirmCancel.addEventListener("click", cancel);
    refs.confirmBackdrop.addEventListener("click", backdrop);
    refs.confirmCancel.focus();
  });
}

function toast(type, title, message) {
  const node = document.createElement("div");
  node.className = `toast ${type}`;
  node.innerHTML = `<span class="toast-bar"></span><div><strong>${escapeHTML(title)}</strong><p>${escapeHTML(message)}</p></div><button type="button" aria-label="Meldung schließen">×</button>`;
  node.querySelector("button").addEventListener("click", () => node.remove());
  refs.toastRegion.appendChild(node);
  setTimeout(() => node.remove(), 6000);
}

function loadingMarkup(message) {
  return `<div class="loading-state"><div><div class="spinner"></div>${escapeHTML(message)}</div></div>`;
}

function errorState(message) {
  return emptyState("!", "Daten konnten nicht geladen werden", message, '<button class="button primary" data-action="retry">Erneut versuchen</button>');
}

function emptyState(icon, title, message, action) {
  return `<div class="empty-state"><div class="empty-state-icon">${escapeHTML(icon)}</div><h2>${escapeHTML(title)}</h2><p>${escapeHTML(message)}</p>${action}</div>`;
}

function emptyInline(message) {
  return `<div class="empty-state empty-inline"><p>${escapeHTML(message)}</p></div>`;
}

bootstrap();
