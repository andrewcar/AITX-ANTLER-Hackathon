// VulnSwarm extension popup — pipeline proof.
// Flow: login -> store token -> read current tab URL -> POST /scan -> show finding.

// Default to the tower's LAN IP so the laptop works out of the box.
// Each person can override it in the popup (stored per-browser). If you point it
// at a NEW host, that host must also be added to host_permissions in manifest.json.
const DEFAULT_API = "http://10.0.0.32:8000";

const $ = (id) => document.getElementById(id);

async function getApi() {
  const { api } = await chrome.storage.local.get("api");
  return api || DEFAULT_API;
}
async function setApi(api) {
  await chrome.storage.local.set({ api });
}

async function getToken() {
  const { token } = await chrome.storage.local.get("token");
  return token || null;
}
async function setToken(token, email) {
  await chrome.storage.local.set({ token, email });
}
async function clearToken() {
  await chrome.storage.local.remove(["token", "email"]);
}

async function currentTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url || "";
}

function showScanView(email) {
  $("loginView").classList.add("hidden");
  $("scanView").classList.remove("hidden");
  $("who").textContent = email;
}
function showLoginView() {
  $("scanView").classList.add("hidden");
  $("loginView").classList.remove("hidden");
}

async function login() {
  $("loginMsg").textContent = "";
  try {
    // persist whatever backend URL the user typed before logging in
    const typed = $("api").value.trim();
    if (typed) await setApi(typed);
    const api = await getApi();
    const res = await fetch(`${api}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: $("email").value, password: $("password").value }),
    });
    if (!res.ok) {
      $("loginMsg").textContent = "Login failed (" + res.status + ")";
      return;
    }
    const data = await res.json();
    await setToken(data.token, data.email);
    await enterScanView();
  } catch (e) {
    $("loginMsg").textContent = "Cannot reach backend. Is it running on :8000?";
  }
}

async function enterScanView() {
  const { email } = await chrome.storage.local.get("email");
  showScanView(email || "?");
  $("target").textContent = await currentTabUrl();
}

async function scan() {
  const token = await getToken();
  const url = await currentTabUrl();
  $("results").innerHTML = '<div class="muted">Scanning…</div>';
  try {
    const api = await getApi();
    const res = await fetch(`${api}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ url }),
    });
    if (res.status === 401) {
      await clearToken();
      showLoginView();
      return;
    }
    const data = await res.json();
    if (!res.ok) {
      $("results").innerHTML = `<div class="err">${data.detail || "scan error"}</div>`;
      return;
    }
    renderFindings(data.findings || []);
  } catch (e) {
    $("results").innerHTML = '<div class="err">Backend unreachable.</div>';
  }
}

function renderFindings(findings) {
  if (!findings.length) {
    $("results").innerHTML = '<div class="ok">No findings.</div>';
    return;
  }
  $("results").innerHTML =
    '<div class="ok">Pipeline OK — ' + findings.length + ' finding(s):</div>' +
    findings
      .map(
        (f) => `
      <div class="finding">
        <span class="sev">${f.severity}</span> <strong>${f.title}</strong>
        <div class="muted">${f.layer} · ${f.verified ? "verified" : "unverified"}</div>
        <div class="muted">${f.evidence}</div>
        <div><em>Fix:</em> ${f.fix}</div>
      </div>`
      )
      .join("");
}

// wire up
$("loginBtn").addEventListener("click", login);
$("scanBtn").addEventListener("click", scan);
$("logout").addEventListener("click", async (e) => {
  e.preventDefault();
  await clearToken();
  showLoginView();
});

// on open: prefill the backend URL field; if we already have a token, go to scan view
(async () => {
  $("api").value = await getApi();
  if (await getToken()) await enterScanView();
})();
