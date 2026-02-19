const apiBaseInput = document.getElementById("apiBase");
const saveEndpointBtn = document.getElementById("saveEndpoint");
const refreshAllBtn = document.getElementById("refreshAll");

const statNetwork = document.getElementById("statNetwork");
const statHeight = document.getElementById("statHeight");
const statUtxo = document.getElementById("statUtxo");
const statWork = document.getElementById("statWork");
const latestRange = document.getElementById("latestRange");
const latestBlocksBody = document.getElementById("latestBlocksBody");

const blockLookupForm = document.getElementById("blockLookupForm");
const blockHeightInput = document.getElementById("blockHeightInput");
const blockLookupOut = document.getElementById("blockLookupOut");

const txLookupForm = document.getElementById("txLookupForm");
const txHeightInput = document.getElementById("txHeightInput");
const txIndexInput = document.getElementById("txIndexInput");
const txLookupOut = document.getElementById("txLookupOut");

const mempoolOut = document.getElementById("mempoolOut");
const walletOut = document.getElementById("walletOut");

const state = {
  apiBase: localStorage.getItem("scam.console.apiBase") || window.location.origin,
};

function parseNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function shortHash(hex, head = 12, tail = 8) {
  if (typeof hex !== "string") return "-";
  if (hex.length <= head + tail + 3) return hex;
  return `${hex.slice(0, head)}...${hex.slice(-tail)}`;
}

function formatJson(data) {
  return JSON.stringify(data, null, 2);
}

function setResult(el, data, isError = false) {
  el.textContent = typeof data === "string" ? data : formatJson(data);
  el.classList.toggle("error", isError);
}

function endpoint(path) {
  const base = state.apiBase.replace(/\/$/, "");
  return `${base}${path}`;
}

async function request(path, { method = "GET", body } = {}) {
  const opts = {
    method,
    headers: {},
  };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const response = await fetch(endpoint(path), opts);
  const text = await response.text();
  let payload = text;
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    // keep raw text
  }
  if (!response.ok) {
    const errorMessage =
      typeof payload === "object" && payload && payload.error
        ? payload.error
        : `HTTP ${response.status}: ${text || response.statusText}`;
    throw new Error(errorMessage);
  }
  return payload;
}

async function loadStatus() {
  const status = await request("/status");
  statNetwork.textContent = status.network_id || "-";
  statHeight.textContent = `${status.tip_height ?? "-"}`;
  statUtxo.textContent = `${status.utxo_count ?? "-"}`;
  statWork.textContent = status.cumulative_work || "-";
  return status;
}

function renderLatestBlocks(blocks, tipHeight) {
  latestBlocksBody.innerHTML = "";
  for (const block of blocks) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${block.height}</td>
      <td class="mono" title="${block.hash}">${shortHash(block.hash)}</td>
      <td>${block.tx_count}</td>
      <td>${block.timestamp}</td>
      <td class="mono" title="${block.target}">${shortHash(block.target, 10, 8)}</td>
    `;
    latestBlocksBody.appendChild(row);
  }
  const first = blocks.length ? blocks[blocks.length - 1].height : tipHeight;
  latestRange.textContent = `${first}..${tipHeight}`;
}

async function loadLatestBlocks(tipHeight, count = 12) {
  if (!Number.isFinite(tipHeight)) {
    renderLatestBlocks([], 0);
    return;
  }
  const heights = [];
  for (let h = tipHeight; h >= 0 && heights.length < count; h -= 1) {
    heights.push(h);
  }

  const requests = heights.map(async (height) => {
    const block = await request(`/block/${height}`);
    return {
      height,
      hash: block.hash,
      tx_count: block.tx_count,
      timestamp: block.timestamp,
      target: block.target,
    };
  });

  const blocks = await Promise.all(requests);
  renderLatestBlocks(blocks, tipHeight);
}

async function loadMempool() {
  try {
    const mempool = await request("/mempool");
    setResult(mempoolOut, mempool);
  } catch (error) {
    setResult(mempoolOut, `Cannot load mempool snapshot: ${error.message}`, true);
  }
}

async function refreshDashboard() {
  try {
    const status = await loadStatus();
    await Promise.all([loadLatestBlocks(status.tip_height), loadMempool()]);
  } catch (error) {
    setResult(blockLookupOut, `Dashboard refresh failed: ${error.message}`, true);
    setResult(txLookupOut, `Dashboard refresh failed: ${error.message}`, true);
    setResult(mempoolOut, `Dashboard refresh failed: ${error.message}`, true);
  }
}

function serializeForm(form) {
  const fd = new FormData(form);
  const out = {};
  for (const [k, v] of fd.entries()) {
    out[k] = typeof v === "string" ? v.trim() : v;
  }
  return out;
}

function initTabs() {
  const tabButtons = document.querySelectorAll(".tab");
  const tabPanels = document.querySelectorAll(".tab-panel");
  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const target = button.dataset.tab;
      tabButtons.forEach((el) => el.classList.toggle("active", el === button));
      tabPanels.forEach((panel) => {
        panel.classList.toggle("active", panel.dataset.panel === target);
      });
    });
  });
}

function initExplorerActions() {
  blockLookupForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const height = parseNumber(blockHeightInput.value, 0);
    try {
      const block = await request(`/block/${height}`);
      setResult(blockLookupOut, block);
    } catch (error) {
      setResult(blockLookupOut, error.message, true);
    }
  });

  txLookupForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const height = parseNumber(txHeightInput.value, 0);
    const index = parseNumber(txIndexInput.value, 0);
    try {
      const tx = await request(`/tx/${height}/${index}`);
      setResult(txLookupOut, tx);
    } catch (error) {
      setResult(txLookupOut, error.message, true);
    }
  });
}

function initWalletActions() {
  document.getElementById("walletNewForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const raw = serializeForm(event.currentTarget);
    const payload = {
      words: parseNumber(raw.words, 12),
      passphrase: raw.passphrase || "",
      account: parseNumber(raw.account, 0),
      index: parseNumber(raw.index, 0),
      ...(raw.hrp ? { hrp: raw.hrp } : {}),
    };
    try {
      const data = await request("/wallet/new", { method: "POST", body: payload });
      setResult(walletOut, data);
    } catch (error) {
      setResult(walletOut, error.message, true);
    }
  });

  document
    .getElementById("walletAddressForm")
    .addEventListener("submit", async (event) => {
      event.preventDefault();
      const raw = serializeForm(event.currentTarget);
      const payload = {
        mnemonic: raw.mnemonic,
        passphrase: raw.passphrase || "",
        account: parseNumber(raw.account, 0),
        index: parseNumber(raw.index, 0),
        ...(raw.hrp ? { hrp: raw.hrp } : {}),
      };
      try {
        const data = await request("/wallet/address", { method: "POST", body: payload });
        setResult(walletOut, data);
      } catch (error) {
        setResult(walletOut, error.message, true);
      }
    });

  document
    .getElementById("walletBalanceForm")
    .addEventListener("submit", async (event) => {
      event.preventDefault();
      const raw = serializeForm(event.currentTarget);
      const payload = {
        mnemonic: raw.mnemonic,
        passphrase: raw.passphrase || "",
        account: parseNumber(raw.account, 0),
        index: parseNumber(raw.index, 0),
      };
      try {
        const data = await request("/wallet/balance", { method: "POST", body: payload });
        setResult(walletOut, data);
      } catch (error) {
        setResult(walletOut, error.message, true);
      }
    });

  document.getElementById("walletSendForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const raw = serializeForm(event.currentTarget);
    const payload = {
      mnemonic: raw.mnemonic,
      passphrase: raw.passphrase || "",
      to: raw.to,
      amount: parseNumber(raw.amount, 0),
      fee: parseNumber(raw.fee, 1),
      account: parseNumber(raw.account, 0),
      index: parseNumber(raw.index, 0),
    };
    try {
      const data = await request("/wallet/send", { method: "POST", body: payload });
      setResult(walletOut, data);
      await refreshDashboard();
    } catch (error) {
      setResult(walletOut, error.message, true);
    }
  });

  document.getElementById("walletDecodeForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const raw = serializeForm(event.currentTarget);
    try {
      const data = await request("/wallet/decode", {
        method: "POST",
        body: { address: raw.address },
      });
      setResult(walletOut, data);
    } catch (error) {
      setResult(walletOut, error.message, true);
    }
  });

  document.getElementById("walletQrForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const raw = serializeForm(event.currentTarget);
    const payload = {
      address: raw.address,
      ...(raw.amount ? { amount: parseNumber(raw.amount, 0) } : {}),
      ...(raw.label ? { label: raw.label } : {}),
    };
    try {
      const data = await request("/wallet/qr", { method: "POST", body: payload });
      setResult(walletOut, data);
    } catch (error) {
      setResult(walletOut, error.message, true);
    }
  });
}

function initEndpointControls() {
  apiBaseInput.value = state.apiBase;

  saveEndpointBtn.addEventListener("click", async () => {
    state.apiBase = apiBaseInput.value.trim().replace(/\/$/, "");
    localStorage.setItem("scam.console.apiBase", state.apiBase);
    await refreshDashboard();
  });

  refreshAllBtn.addEventListener("click", async () => {
    await refreshDashboard();
  });
}

async function bootstrap() {
  initTabs();
  initEndpointControls();
  initExplorerActions();
  initWalletActions();
  await refreshDashboard();
  setInterval(() => {
    refreshDashboard().catch((error) => {
      setResult(mempoolOut, `Auto refresh failed: ${error.message}`, true);
    });
  }, 5000);
}

bootstrap();
