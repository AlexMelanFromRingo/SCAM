const apiBaseInput = document.getElementById("apiBase");
const saveEndpointBtn = document.getElementById("saveEndpoint");
const refreshAllBtn = document.getElementById("refreshAll");
const liveStatus = document.getElementById("liveStatus");
const liveMode = document.getElementById("liveMode");

const statNetwork = document.getElementById("statNetwork");
const statHeight = document.getElementById("statHeight");
const statUtxo = document.getElementById("statUtxo");
const statWork = document.getElementById("statWork");
const statRelayPeers = document.getElementById("statRelayPeers");
const statSyncLag = document.getElementById("statSyncLag");
const statSyncLagDetail = document.getElementById("statSyncLagDetail");
const statLastBlockAge = document.getElementById("statLastBlockAge");
const statRelayMempool = document.getElementById("statRelayMempool");
const statNetworkHashrate = document.getElementById("statNetworkHashrate");
const statPoolHashrate = document.getElementById("statPoolHashrate");
const statPoolWorkers = document.getElementById("statPoolWorkers");
const statSystemTime = document.getElementById("statSystemTime");
const statDifficulty = document.getElementById("statDifficulty");
const latestRange = document.getElementById("latestRange");
const latestBlocksBody = document.getElementById("latestBlocksBody");

const blockLookupForm = document.getElementById("blockLookupForm");
const blockHeightInput = document.getElementById("blockHeightInput");
const blockLookupOut = document.getElementById("blockLookupOut");
const blockLookupViewCardBtn = document.getElementById("blockLookupViewCard");
const blockLookupViewRawBtn = document.getElementById("blockLookupViewRaw");

const txLookupForm = document.getElementById("txLookupForm");
const txHeightInput = document.getElementById("txHeightInput");
const txIndexInput = document.getElementById("txIndexInput");
const txidLookupForm = document.getElementById("txidLookupForm");
const txidInput = document.getElementById("txidInput");
const txLookupOut = document.getElementById("txLookupOut");
const txLookupViewCardBtn = document.getElementById("txLookupViewCard");
const txLookupViewRawBtn = document.getElementById("txLookupViewRaw");

const mempoolOut = document.getElementById("mempoolOut");
const poolStatusForm = document.getElementById("poolStatusForm");
const poolStatusOut = document.getElementById("poolStatusOut");
const poolWorkerForm = document.getElementById("poolWorkerForm");
const poolWorkerInput = document.getElementById("poolWorkerInput");
const poolWorkerOut = document.getElementById("poolWorkerOut");
const poolPayoutPendingOut = document.getElementById("poolPayoutPendingOut");
const poolPayoutCompletedOut = document.getElementById("poolPayoutCompletedOut");
const walletOut = document.getElementById("walletOut");

const DASHBOARD_POLL_INTERVAL_MS = 5000;

const state = {
  apiBase: localStorage.getItem("scam.console.apiBase") || window.location.origin,
  events: null,
  lastTipHeight: null,
  lastMempoolCount: null,
  lookupView: {
    block: localStorage.getItem("scam.console.lookupView.block") || "card",
    tx: localStorage.getItem("scam.console.lookupView.tx") || "card",
  },
  lookupCache: {
    block: null,
    tx: null,
    blockError: "",
    txError: "",
  },
  latestTarget: null,
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

function formatAgeSeconds(sec) {
  const n = Number(sec);
  if (!Number.isFinite(n) || n < 0) return "-";
  if (n < 60) return `${Math.floor(n)}s`;
  if (n < 3600) return `${Math.floor(n / 60)}m ${Math.floor(n % 60)}s`;
  return `${Math.floor(n / 3600)}h ${Math.floor((n % 3600) / 60)}m`;
}

function formatHashrate(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return "-";
  if (n >= 1e18) return `${(n / 1e18).toFixed(2)} EH/s`;
  if (n >= 1e15) return `${(n / 1e15).toFixed(2)} PH/s`;
  if (n >= 1e12) return `${(n / 1e12).toFixed(2)} TH/s`;
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)} GH/s`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)} MH/s`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(2)} KH/s`;
  return `${n.toFixed(2)} H/s`;
}

function formatSyncLagDetail(localLag, telemetryAgeSec) {
  const local = Number(localLag);
  const age = Number(telemetryAgeSec);
  const localText = Number.isFinite(local) ? `${Math.max(0, Math.floor(local))} blk` : "-";
  const ageText = Number.isFinite(age) ? formatAgeSeconds(Math.max(0, age)) : "-";
  return `local: ${localText} | telemetry age: ${ageText}`;
}

function formatSystemTime24h(date = new Date()) {
  return date.toLocaleTimeString([], {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatJson(data) {
  return JSON.stringify(data, null, 2);
}

function setResult(el, data, isError = false) {
  el.innerHTML = "";
  el.textContent = typeof data === "string" ? data : formatJson(data);
  el.classList.toggle("error", isError);
}

function setTextIfPresent(el, value, format = (v) => `${v}`) {
  if (value === null || value === undefined || Number.isNaN(value)) return;
  el.textContent = format(value);
}

function formatUnixTimestamp(unixSec) {
  const sec = Number(unixSec);
  if (!Number.isFinite(sec)) return "-";
  const d = new Date(sec * 1000);
  if (Number.isNaN(d.getTime())) return `${unixSec}`;
  return `${d.toISOString()} (${sec})`;
}

function renderLookupKvGrid(items) {
  return `
    <div class="lookup-kv-grid">
      ${items
        .map(
          (item) => `
            <article class="lookup-kv-card ${escapeHtml(item.wide ? "wide" : "")}">
              <div class="lookup-kv-label">${escapeHtml(item.label)}</div>
              <div class="lookup-kv-value ${escapeHtml(item.mono ? "mono" : "")}" title="${escapeHtml(item.title ?? item.value ?? "-")}">
                ${escapeHtml(item.value ?? "-")}
              </div>
            </article>
          `,
        )
        .join("")}
    </div>
  `;
}

function renderBlockLookupCard(block) {
  if (!block || typeof block !== "object") {
    return `<div class="wallet-history-empty">No block payload loaded yet.</div>`;
  }
  const txs = Array.isArray(block.transactions) ? block.transactions : [];
  return `
    <section class="lookup-card-layout">
      <header class="lookup-card-header">
        <h3>Block #${escapeHtml(block.height ?? "-")}</h3>
        <span class="wallet-history-badge self">${escapeHtml((block.tx_count ?? txs.length ?? 0).toString())} tx</span>
      </header>
      ${renderLookupKvGrid([
        { label: "Hash", value: block.hash ?? "-", mono: true, wide: true },
        { label: "Prev Hash", value: block.prev_hash ?? "-", mono: true, wide: true },
        { label: "Timestamp", value: formatUnixTimestamp(block.timestamp) },
        { label: "Target", value: block.target ?? "-", mono: true, wide: true },
        { label: "Merkle Root", value: block.merkle_root ?? "-", mono: true, wide: true },
        { label: "Version", value: block.version ?? "-" },
        { label: "Nonce", value: block.nonce ?? "-" },
      ])}
      ${
        txs.length
          ? `<section class="lookup-subsection">
              <div class="lookup-subsection-title">Transactions (${txs.length})</div>
              <div class="lookup-chip-list">
                ${txs
                  .map((tx, index) => {
                    const txid = tx && typeof tx === "object" ? tx.txid ?? shortHash(JSON.stringify(tx)) : `${tx}`;
                    return `<span class="lookup-chip mono" title="${escapeHtml(txid)}">#${index}: ${escapeHtml(shortHash(txid, 18, 12))}</span>`;
                  })
                  .join("")}
              </div>
            </section>`
          : `<div class="wallet-history-empty">Detailed transaction list is not available in this response. Use TX Lookup for full tx body.</div>`
      }
    </section>
  `;
}

function renderTxInputRow(input, index) {
  const pubkey = input?.pubkey_compressed_hex ?? "-";
  return `
    <article class="lookup-io-card">
      <div class="lookup-io-head">
        <span class="lookup-chip">Input #${index}</span>
        <span class="lookup-chip mono">${escapeHtml((input?.prev_vout ?? "-").toString())}</span>
      </div>
      <div class="lookup-io-line mono" title="${escapeHtml(input?.prev_txid ?? "-")}">prev_txid: ${escapeHtml(shortHash(input?.prev_txid ?? "-", 16, 12))}</div>
      <div class="lookup-io-line">sequence: ${escapeHtml((input?.sequence ?? "-").toString())}</div>
      <div class="lookup-io-line mono" title="${escapeHtml(pubkey)}">pubkey: ${escapeHtml(shortHash(pubkey, 16, 10))}</div>
      <div class="lookup-io-line">coinbase_input: ${escapeHtml(Boolean(input?.is_coinbase_input).toString())}</div>
    </article>
  `;
}

function renderTxOutputRow(output, index) {
  const keyHash = output?.key_hash20_hex ?? "-";
  return `
    <article class="lookup-io-card">
      <div class="lookup-io-head">
        <span class="lookup-chip">Output #${index}</span>
        <span class="lookup-chip">${escapeHtml(formatScamOnly(output?.value ?? 0))}</span>
      </div>
      <div class="lookup-io-line">atomic: ${escapeHtml(formatAtomicOnly(output?.value ?? 0))}</div>
      <div class="lookup-io-line mono" title="${escapeHtml(keyHash)}">key_hash20: ${escapeHtml(shortHash(keyHash, 18, 10))}</div>
    </article>
  `;
}

function renderTxLookupCard(tx) {
  if (!tx || typeof tx !== "object") {
    return `<div class="wallet-history-empty">No transaction payload loaded yet.</div>`;
  }
  const inputs = Array.isArray(tx.inputs) ? tx.inputs : [];
  const outputs = Array.isArray(tx.outputs) ? tx.outputs : [];
  return `
    <section class="lookup-card-layout">
      <header class="lookup-card-header">
        <h3>Transaction</h3>
        <span class="wallet-history-badge ${tx.coinbase ? "coinbase" : "self"}">${tx.coinbase ? "Coinbase" : "Regular"}</span>
      </header>
      ${renderLookupKvGrid([
        { label: "TxID", value: tx.txid ?? "-", mono: true, wide: true },
        { label: "Block Height", value: tx.block_height ?? "-" },
        { label: "Tx Index", value: tx.tx_index ?? "-" },
        { label: "Version", value: tx.version ?? "-" },
        { label: "Lock Time", value: tx.lock_time ?? "-" },
        { label: "Input Count", value: tx.input_count ?? inputs.length ?? 0 },
        { label: "Output Count", value: tx.output_count ?? outputs.length ?? 0 },
      ])}
      <section class="lookup-subsection">
        <div class="lookup-subsection-title">Inputs (${inputs.length})</div>
        ${
          inputs.length
            ? `<div class="lookup-io-grid">${inputs.map((input, index) => renderTxInputRow(input, index)).join("")}</div>`
            : `<div class="wallet-history-empty">No inputs in payload.</div>`
        }
      </section>
      <section class="lookup-subsection">
        <div class="lookup-subsection-title">Outputs (${outputs.length})</div>
        ${
          outputs.length
            ? `<div class="lookup-io-grid">${outputs.map((output, index) => renderTxOutputRow(output, index)).join("")}</div>`
            : `<div class="wallet-history-empty">No outputs in payload.</div>`
        }
      </section>
    </section>
  `;
}

function setLookupToggleState(kind) {
  const isBlock = kind === "block";
  const mode = state.lookupView[kind] === "raw" ? "raw" : "card";
  const cardBtn = isBlock ? blockLookupViewCardBtn : txLookupViewCardBtn;
  const rawBtn = isBlock ? blockLookupViewRawBtn : txLookupViewRawBtn;
  if (!cardBtn || !rawBtn) return;
  cardBtn.classList.toggle("active", mode === "card");
  rawBtn.classList.toggle("active", mode === "raw");
}

function renderBlockLookupResult() {
  const error = state.lookupCache.blockError;
  const data = state.lookupCache.block;
  if (error) {
    setResult(blockLookupOut, error, true);
    return;
  }
  if (!data) {
    setResult(blockLookupOut, "No block loaded yet.", false);
    return;
  }
  if (state.lookupView.block === "raw") {
    setResult(blockLookupOut, data, false);
    return;
  }
  blockLookupOut.classList.remove("error");
  blockLookupOut.innerHTML = renderBlockLookupCard(data);
}

function renderTxLookupResult() {
  const error = state.lookupCache.txError;
  const data = state.lookupCache.tx;
  if (error) {
    setResult(txLookupOut, error, true);
    return;
  }
  if (!data) {
    setResult(txLookupOut, "No transaction loaded yet.", false);
    return;
  }
  if (state.lookupView.tx === "raw") {
    setResult(txLookupOut, data, false);
    return;
  }
  txLookupOut.classList.remove("error");
  txLookupOut.innerHTML = renderTxLookupCard(data);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function isWalletBalancePayload(data) {
  return (
    data &&
    typeof data === "object" &&
    "address" in data &&
    "tip_height" in data &&
    "spendable" in data &&
    "immature" in data
  );
}

function isWalletBalanceHistoryPayload(data) {
  return (
    data &&
    typeof data === "object" &&
    data.balance &&
    typeof data.balance === "object" &&
    Array.isArray(data.tx_history)
  );
}

function isWalletSendPayload(data) {
  return (
    data &&
    typeof data === "object" &&
    "txid" in data &&
    "mempool_outcome" in data &&
    "amount" in data &&
    "fee" in data
  );
}

function formatScamOnly(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return `${value}`;
  return `${(n / 1e8).toLocaleString(undefined, {
    minimumFractionDigits: 8,
    maximumFractionDigits: 8,
  })} SCAM`;
}

function formatAtomicOnly(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return `${value}`;
  return `${n.toLocaleString()} atomic`;
}

function getWalletBalanceStatus(total, spendable, immature) {
  if (total <= 0) {
    return {
      kind: "empty",
      title: "No Funds",
      detail: "This address has no UTXOs yet.",
    };
  }
  if (spendable <= 0 && immature > 0) {
    return {
      kind: "immature",
      title: "Immature Balance",
      detail: "Mining rewards are locked by coinbase maturity.",
    };
  }
  if (spendable > 0 && immature > 0) {
    return {
      kind: "partial",
      title: "Partially Spendable",
      detail: "Some UTXOs are spendable, some are still maturing.",
    };
  }
  return {
    kind: "ready",
    title: "Spendable",
    detail: "All detected funds are currently spendable.",
  };
}

function balanceLineHtml(label, valueAtomic, pct, tone) {
  const boundedPct = Math.min(100, Math.max(0, Number(pct) || 0));
  return `
    <article class="wallet-balance-card">
      <div class="wallet-balance-card-head">
        <span class="wallet-balance-label">${escapeHtml(label)}</span>
        <span class="wallet-balance-pct">${boundedPct.toFixed(2)}%</span>
      </div>
      <div class="wallet-balance-value">${escapeHtml(formatScamOnly(valueAtomic))}</div>
      <div class="wallet-balance-atomic">${escapeHtml(formatAtomicOnly(valueAtomic))}</div>
      <div class="wallet-balance-progress ${escapeHtml(tone)}"><span style="width:${boundedPct}%"></span></div>
    </article>
  `;
}

function renderWalletBalanceCard(data) {
  const total = Number(data.total) || 0;
  const spendable = Number(data.spendable) || 0;
  const immature = Number(data.immature) || 0;
  const spendablePct = total > 0 ? (spendable / total) * 100 : 0;
  const immaturePct = total > 0 ? (immature / total) * 100 : 0;
  const status = getWalletBalanceStatus(total, spendable, immature);
  return `
    <section class="wallet-balance-layout">
      <header class="wallet-balance-summary">
        <div>
          <h3>Wallet Balance</h3>
          <div class="wallet-balance-subtitle">${escapeHtml(status.detail)}</div>
        </div>
        <span class="wallet-balance-status ${escapeHtml(status.kind)}">${escapeHtml(status.title)}</span>
      </header>

      <div class="wallet-meta-grid">
        <div class="wallet-meta-item">
          <span class="wallet-meta-label">Network</span>
          <span class="wallet-meta-value">${escapeHtml(data.network_id ?? "-")}</span>
        </div>
        <div class="wallet-meta-item">
          <span class="wallet-meta-label">Tip Height</span>
          <span class="wallet-meta-value">${escapeHtml(data.tip_height ?? "-")}</span>
        </div>
        <div class="wallet-meta-item wallet-meta-item-wide">
          <span class="wallet-meta-label">Address</span>
          <span class="wallet-meta-value mono">${escapeHtml(data.address ?? "-")}</span>
        </div>
      </div>

      <div class="wallet-balance-grid">
        ${balanceLineHtml("Total", total, 100, "tone-total")}
        ${balanceLineHtml("Spendable", spendable, spendablePct, "tone-spendable")}
        ${balanceLineHtml("Immature", immature, immaturePct, "tone-immature")}
      </div>

      <div class="wallet-utxo-grid">
        <article class="wallet-utxo-card">
          <div class="wallet-utxo-label">UTXOs Total</div>
          <div class="wallet-utxo-value">${(data.utxo_count ?? 0).toLocaleString()}</div>
        </article>
        <article class="wallet-utxo-card">
          <div class="wallet-utxo-label">Spendable UTXOs</div>
          <div class="wallet-utxo-value">${(data.spendable_utxo_count ?? 0).toLocaleString()}</div>
        </article>
        <article class="wallet-utxo-card">
          <div class="wallet-utxo-label">Immature UTXOs</div>
          <div class="wallet-utxo-value">${(data.immature_utxo_count ?? 0).toLocaleString()}</div>
        </article>
      </div>
    </section>
  `;
}

function txDirectionMeta(direction, coinbase) {
  if (coinbase) {
    return {
      cls: "coinbase",
      title: "Coinbase",
      flow: "Block reward -> your wallet",
      sign: "+",
    };
  }
  if (direction === "in") {
    return {
      cls: "in",
      title: "Incoming",
      flow: "Sender -> your wallet",
      sign: "+",
    };
  }
  if (direction === "out") {
    return {
      cls: "out",
      title: "Outgoing",
      flow: "Your wallet -> recipient(s)",
      sign: "-",
    };
  }
  return {
    cls: "self",
    title: "Self",
    flow: "Your wallet -> your wallet",
    sign: "±",
  };
}

function renderWalletHistorySection(txHistory, historyError = "") {
  const entries = Array.isArray(txHistory) ? txHistory : [];
  let bodyHtml = "";
  if (!entries.length) {
    bodyHtml = `
      <div class="wallet-history-empty">
        No transactions detected for this wallet yet.
      </div>
    `;
  } else {
    bodyHtml = `
      <div class="wallet-history-grid">
        ${entries
          .map((entry) => {
            const direction = txDirectionMeta(entry.direction, entry.coinbase);
            const netAtomic = Number(entry.net) || 0;
            return `
              <article class="wallet-history-card">
                <div class="wallet-history-head">
                  <span class="wallet-history-badge ${escapeHtml(direction.cls)}">${escapeHtml(direction.title)}</span>
                  <span class="wallet-history-height">H${escapeHtml(entry.height ?? "-")}</span>
                </div>
                <div class="wallet-history-net">${escapeHtml(direction.sign)}${escapeHtml(formatScamOnly(netAtomic))}</div>
                <div class="wallet-history-flow">${escapeHtml(direction.flow)}</div>
                <div class="wallet-history-amounts">
                  <span>Received: ${escapeHtml(formatScamOnly(entry.received ?? 0))}</span>
                  <span>Sent: ${escapeHtml(formatScamOnly(entry.sent ?? 0))}</span>
                </div>
                <div class="wallet-history-txid mono" title="${escapeHtml(entry.txid ?? "-")}">
                  ${escapeHtml(shortHash(entry.txid ?? "-", 16, 12))}
                </div>
              </article>
            `;
          })
          .join("")}
      </div>
    `;
  }

  return `
    <section class="wallet-history-layout">
      <header class="wallet-history-header">
        <h3>Transaction History</h3>
        <span class="wallet-history-count">${entries.length} entries</span>
      </header>
      ${
        historyError
          ? `<div class="wallet-history-warning">History temporarily unavailable: ${escapeHtml(historyError)}</div>`
          : ""
      }
      ${bodyHtml}
    </section>
  `;
}

function renderWalletBalanceWithHistory(payload) {
  const balance = payload.balance;
  return `
    ${renderWalletBalanceCard(balance)}
    ${renderWalletHistorySection(payload.tx_history, payload.history_error || "")}
  `;
}

function sendOutcomeMeta(outcome) {
  switch (outcome) {
    case "accepted":
      return { cls: "accepted", title: "Accepted", detail: "Transaction accepted into mempool." };
    case "replaced":
      return { cls: "accepted", title: "Replaced", detail: "Accepted and replaced conflicting transaction(s)." };
    case "accepted_with_eviction":
      return { cls: "accepted", title: "Accepted (evicted)", detail: "Accepted with low-fee eviction from mempool." };
    case "already_present":
      return { cls: "neutral", title: "Already Present", detail: "This transaction already exists in mempool." };
    case "rejected_conflict_insufficient_fee":
      return { cls: "rejected", title: "Rejected", detail: "Conflict replacement fee was too low." };
    case "rejected_conflict_insufficient_feerate":
      return { cls: "rejected", title: "Rejected", detail: "Conflict replacement feerate was too low." };
    default:
      return { cls: "neutral", title: outcome || "Unknown", detail: "Mempool returned an unclassified outcome." };
  }
}

function renderWalletSendCard(data) {
  const outcome = sendOutcomeMeta(data.mempool_outcome);
  const selectedInputs = Array.isArray(data.selected_inputs) ? data.selected_inputs : [];
  return `
    <section class="wallet-send-layout">
      <header class="wallet-send-summary">
        <div>
          <h3>Transaction Submit Result</h3>
          <div class="wallet-send-subtitle">${escapeHtml(outcome.detail)}</div>
        </div>
        <span class="wallet-send-status ${escapeHtml(outcome.cls)}">${escapeHtml(outcome.title)}</span>
      </header>

      <div class="wallet-meta-grid">
        <div class="wallet-meta-item">
          <span class="wallet-meta-label">Network</span>
          <span class="wallet-meta-value">${escapeHtml(data.network_id ?? "-")}</span>
        </div>
        <div class="wallet-meta-item">
          <span class="wallet-meta-label">Mempool Outcome</span>
          <span class="wallet-meta-value">${escapeHtml(data.mempool_outcome ?? "-")}</span>
        </div>
        <div class="wallet-meta-item wallet-meta-item-wide">
          <span class="wallet-meta-label">TxID</span>
          <span class="wallet-meta-value mono">${escapeHtml(data.txid ?? "-")}</span>
        </div>
      </div>

      <div class="wallet-balance-grid">
        ${balanceLineHtml("Amount", data.amount ?? 0, 100, "tone-total")}
        ${balanceLineHtml("Fee", data.fee ?? 0, 100, "tone-immature")}
        ${balanceLineHtml("Change", data.change ?? 0, 100, "tone-spendable")}
      </div>

      <div class="wallet-send-inputs">
        <div class="wallet-send-inputs-title">Selected Inputs (${selectedInputs.length})</div>
        ${
          selectedInputs.length
            ? `<div class="wallet-send-input-list">
                ${selectedInputs
                  .map(
                    (input) => `
                      <article class="wallet-send-input-card">
                        <div class="mono" title="${escapeHtml(input.txid ?? "-")}">
                          ${escapeHtml(shortHash(input.txid ?? "-", 16, 12))}:${escapeHtml(input.vout ?? "-")}
                        </div>
                        <div>${escapeHtml(formatScamOnly(input.value ?? 0))}</div>
                      </article>
                    `,
                  )
                  .join("")}
              </div>`
            : `<div class="wallet-history-empty">No input details returned by RPC.</div>`
        }
      </div>
    </section>
  `;
}

function setWalletResult(data, isError = false) {
  if (!isError && isWalletBalanceHistoryPayload(data)) {
    walletOut.innerHTML = renderWalletBalanceWithHistory(data);
    walletOut.classList.remove("error");
    return;
  }
  if (!isError && isWalletBalancePayload(data)) {
    walletOut.innerHTML = renderWalletBalanceCard(data);
    walletOut.classList.remove("error");
    return;
  }
  if (!isError && isWalletSendPayload(data)) {
    walletOut.innerHTML = renderWalletSendCard(data);
    walletOut.classList.remove("error");
    return;
  }
  setResult(walletOut, data, isError);
}

function endpoint(path) {
  const base = state.apiBase.replace(/\/$/, "");
  return `${base}${path}`;
}

function setLiveStatusBadge(mode, text) {
  if (!liveStatus) return;
  liveStatus.classList.remove("connected", "reconnecting", "disconnected");
  liveStatus.classList.add(mode);
  liveStatus.textContent = text;
}

function closeLiveStream() {
  if (state.events) {
    state.events.close();
    state.events = null;
  }
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
  const url = endpoint(path);
  let response;
  let lastError = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      response = await fetch(url, opts);
      lastError = null;
      break;
    } catch (error) {
      lastError = error;
      if (attempt === 0) {
        await new Promise((resolve) => setTimeout(resolve, 200));
      }
    }
  }
  if (!response) {
    const detail = lastError?.message || "network error";
    throw new Error(`Failed to fetch ${url}: ${detail}`);
  }
  const text = await response.text();
  let payload = text;
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    // keep raw text
  }
  if (response.ok && typeof payload === "string") {
    const trimmed = payload.trimStart().toLowerCase();
    if (trimmed.startsWith("<!doctype html") || trimmed.startsWith("<html")) {
      throw new Error(
        "API returned HTML instead of JSON. Проверь apiBase и перезапусти ноду с новым rpc-serve",
      );
    }
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
  setTextIfPresent(statNetwork, status.network_id);
  setTextIfPresent(statHeight, status.tip_height);
  setTextIfPresent(statUtxo, status.utxo_count);
  setTextIfPresent(statWork, status.cumulative_work);
  setTextIfPresent(statNetworkHashrate, status.network_hashrate_hps, formatHashrate);
  setTextIfPresent(statPoolHashrate, status.stratum_pool_hashrate_hps, formatHashrate);
  setTextIfPresent(statPoolWorkers, status.stratum_workers_active);
  return status;
}

function renderLatestBlocks(blocks, tipHeight) {
  // Audit F-10: escape every field from the RPC payload before inlining
  // into HTML attributes/text. Even though the RPC binds to localhost,
  // the page can be reached via DNS rebinding or a proxy on the same
  // host; assume the JSON is attacker-controlled.
  latestBlocksBody.innerHTML = "";
  for (const block of blocks) {
    const row = document.createElement("tr");
    const hash = String(block.hash ?? "");
    const target = String(block.target ?? "");
    row.innerHTML = `
      <td>${escapeHtml(block.height ?? "")}</td>
      <td class="mono" title="${escapeHtml(hash)}">${escapeHtml(shortHash(hash))}</td>
      <td>${escapeHtml(block.tx_count ?? "")}</td>
      <td>${escapeHtml(block.timestamp ?? "")}</td>
      <td class="mono" title="${escapeHtml(target)}">${escapeHtml(shortHash(target, 10, 8))}</td>
    `;
    latestBlocksBody.appendChild(row);
  }
  const first = blocks.length ? blocks[blocks.length - 1].height : tipHeight;
  latestRange.textContent = `${first}..${tipHeight}`;
  if (blocks.length && blocks[0].target) {
    state.latestTarget = blocks[0].target;
    // textContent (not innerHTML) — safe even unescaped.
    statDifficulty.textContent = blocks[0].target;
  }
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
    try {
      const block = await request(`/block/${height}`);
      return {
        height,
        hash: block.hash,
        tx_count: block.tx_count,
        timestamp: block.timestamp,
        target: block.target,
      };
    } catch (error) {
      const msg = String(error?.message || "");
      if (msg.includes("not found")) {
        return null;
      }
      throw error;
    }
  });

  const blocks = (await Promise.all(requests)).filter(Boolean);
  renderLatestBlocks(blocks, tipHeight);
}

async function loadMempool() {
  try {
    const mempool = await request("/mempool");
    const countFromField = Number(mempool.tx_count);
    const countFromTxids = Array.isArray(mempool.txids) ? mempool.txids.length : null;
    if (Number.isFinite(countFromField)) {
      state.lastMempoolCount = countFromField;
    } else if (Number.isFinite(countFromTxids)) {
      state.lastMempoolCount = countFromTxids;
    }
    if (Number.isFinite(state.lastMempoolCount)) {
      statRelayMempool.textContent = `${state.lastMempoolCount}`;
    }
    setResult(mempoolOut, mempool);
  } catch (error) {
    setResult(mempoolOut, `Cannot load mempool snapshot: ${error.message}`, true);
  }
}

async function loadPoolStatus() {
  try {
    const status = await request("/pool/status");
    setResult(poolStatusOut, status);
  } catch (error) {
    setResult(poolStatusOut, `Cannot load pool status: ${error.message}`, true);
  }
}

async function loadPoolPayouts() {
  try {
    const pending = await request("/pool/payouts/pending");
    setResult(poolPayoutPendingOut, pending);
  } catch (error) {
    setResult(poolPayoutPendingOut, `Cannot load pending payouts: ${error.message}`, true);
  }
  try {
    const completed = await request("/pool/payouts/completed");
    setResult(poolPayoutCompletedOut, completed);
  } catch (error) {
    setResult(poolPayoutCompletedOut, `Cannot load completed payouts: ${error.message}`, true);
  }
}

async function refreshDashboard() {
  try {
    const status = await loadStatus();
    state.lastTipHeight = Number.isFinite(Number(status.tip_height))
      ? Number(status.tip_height)
      : state.lastTipHeight;
    await Promise.allSettled([
      loadLatestBlocks(status.tip_height),
      loadMempool(),
      loadPoolStatus(),
      loadPoolPayouts(),
    ]);
  } catch (error) {
    setResult(blockLookupOut, `Dashboard refresh failed: ${error.message}`, true);
    setResult(txLookupOut, `Dashboard refresh failed: ${error.message}`, true);
    setResult(mempoolOut, `Dashboard refresh failed: ${error.message}`, true);
  }
}

function applyLiveSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== "object") return;
  setTextIfPresent(statNetwork, snapshot.network_id);
  setTextIfPresent(statHeight, snapshot.tip_height);
  setTextIfPresent(statUtxo, snapshot.utxo_count);
  setTextIfPresent(statWork, snapshot.cumulative_work);
  setTextIfPresent(statRelayPeers, snapshot.relay_active_peers);
  setTextIfPresent(statSyncLag, snapshot.sync_lag_blocks, (v) => `${v} blk`);
  setTextIfPresent(
    statSyncLagDetail,
    formatSyncLagDetail(snapshot.sync_lag_local_blocks, snapshot.relay_snapshot_age_sec),
    (v) => v,
  );
  setTextIfPresent(statLastBlockAge, snapshot.last_block_age_sec, formatAgeSeconds);
  setTextIfPresent(statRelayMempool, snapshot.relay_mempool_len);
  setTextIfPresent(statNetworkHashrate, snapshot.network_hashrate_hps, formatHashrate);
  setTextIfPresent(statPoolHashrate, snapshot.stratum_pool_hashrate_hps, formatHashrate);
  setTextIfPresent(statPoolWorkers, snapshot.stratum_workers_active);

  const tipHeight = Number(snapshot.tip_height);
  if (Number.isFinite(tipHeight) && tipHeight !== state.lastTipHeight) {
    state.lastTipHeight = tipHeight;
    loadLatestBlocks(tipHeight).catch((error) => {
      setResult(blockLookupOut, `Live latest blocks failed: ${error.message}`, true);
    });
  }

  const mempoolCount = Number(snapshot.mempool_tx_count);
  if (Number.isFinite(mempoolCount) && mempoolCount !== state.lastMempoolCount) {
    state.lastMempoolCount = mempoolCount;
    loadMempool().catch((error) => {
      setResult(mempoolOut, `Live mempool refresh failed: ${error.message}`, true);
    });
  }
}

function startSystemClock() {
  const tick = () => {
    if (statSystemTime) {
      statSystemTime.textContent = formatSystemTime24h();
    }
  };
  tick();
  setInterval(tick, 1000);
}

function startLiveStream() {
  closeLiveStream();
  if (typeof EventSource === "undefined") {
    setLiveStatusBadge("disconnected", "Live stream: unsupported");
    if (liveMode) liveMode.textContent = "Fallback polling: 5s";
    return;
  }

  const events = new EventSource(endpoint("/events"));
  state.events = events;
  setLiveStatusBadge("reconnecting", "Live stream: connecting");
  if (liveMode) liveMode.textContent = "SSE push + polling fallback";

  const onSnapshot = (event) => {
    try {
      const snapshot = JSON.parse(event.data);
      applyLiveSnapshot(snapshot);
    } catch (error) {
      setResult(mempoolOut, `Live snapshot parse failed: ${error.message}`, true);
    }
  };

  events.addEventListener("snapshot", onSnapshot);
  events.onmessage = onSnapshot;
  events.onopen = () => {
    setLiveStatusBadge("connected", "Live stream: connected");
  };
  events.onerror = () => {
    if (state.events !== events) return;
    setLiveStatusBadge("reconnecting", "Live stream: reconnecting");
  };
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
  setLookupToggleState("block");
  setLookupToggleState("tx");
  renderBlockLookupResult();
  renderTxLookupResult();

  blockLookupViewCardBtn?.addEventListener("click", () => {
    state.lookupView.block = "card";
    localStorage.setItem("scam.console.lookupView.block", "card");
    setLookupToggleState("block");
    renderBlockLookupResult();
  });

  blockLookupViewRawBtn?.addEventListener("click", () => {
    state.lookupView.block = "raw";
    localStorage.setItem("scam.console.lookupView.block", "raw");
    setLookupToggleState("block");
    renderBlockLookupResult();
  });

  txLookupViewCardBtn?.addEventListener("click", () => {
    state.lookupView.tx = "card";
    localStorage.setItem("scam.console.lookupView.tx", "card");
    setLookupToggleState("tx");
    renderTxLookupResult();
  });

  txLookupViewRawBtn?.addEventListener("click", () => {
    state.lookupView.tx = "raw";
    localStorage.setItem("scam.console.lookupView.tx", "raw");
    setLookupToggleState("tx");
    renderTxLookupResult();
  });

  blockLookupForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const height = parseNumber(blockHeightInput.value, 0);
    try {
      const block = await request(`/block/${height}`);
      state.lookupCache.block = block;
      state.lookupCache.blockError = "";
      renderBlockLookupResult();
    } catch (error) {
      state.lookupCache.block = null;
      state.lookupCache.blockError = error.message;
      renderBlockLookupResult();
    }
  });

  txLookupForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const height = parseNumber(txHeightInput.value, 0);
    const index = parseNumber(txIndexInput.value, 0);
    try {
      const tx = await request(`/tx/${height}/${index}`);
      state.lookupCache.tx = tx;
      state.lookupCache.txError = "";
      renderTxLookupResult();
    } catch (error) {
      state.lookupCache.tx = null;
      state.lookupCache.txError = error.message;
      renderTxLookupResult();
    }
  });

  txidLookupForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const txid = (txidInput.value || "").trim().toLowerCase();
    if (!txid) {
      state.lookupCache.tx = null;
      state.lookupCache.txError = "txid is required";
      renderTxLookupResult();
      return;
    }
    try {
      const tx = await request(`/txid/${encodeURIComponent(txid)}`);
      state.lookupCache.tx = tx;
      state.lookupCache.txError = "";
      renderTxLookupResult();
    } catch (error) {
      state.lookupCache.tx = null;
      state.lookupCache.txError = error.message;
      renderTxLookupResult();
    }
  });

  if (poolStatusForm) {
    poolStatusForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      await loadPoolStatus();
      await loadPoolPayouts();
    });
  }

  if (poolWorkerForm) {
    poolWorkerForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const worker = (poolWorkerInput.value || "").trim();
      if (!worker) {
        setResult(poolWorkerOut, "worker label is required", true);
        return;
      }
      try {
        const data = await request(`/pool/worker/${encodeURIComponent(worker)}`);
        setResult(poolWorkerOut, data);
      } catch (error) {
        setResult(poolWorkerOut, error.message, true);
      }
    });
  }
}

function initWalletActions() {
  const historyByAddress = async (address, maxEntries = 30) =>
    request("/wallet/balance-history-by-address", {
      method: "POST",
      body: {
        address,
        max_entries: maxEntries,
      },
    });

  document.getElementById("walletNewForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const raw = serializeForm(event.currentTarget);
    const payload = {
      words: parseNumber(raw.words, 12),
      passphrase: raw.passphrase || "",
      seed_mode: raw.seed_mode || "bip39",
      account: parseNumber(raw.account, 0),
      index: parseNumber(raw.index, 0),
      ...(raw.hrp ? { hrp: raw.hrp } : {}),
    };
    try {
      const data = await request("/wallet/new", { method: "POST", body: payload });
      setWalletResult(data);
    } catch (error) {
      setWalletResult(error.message, true);
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
        seed_mode: raw.seed_mode || "bip39",
        account: parseNumber(raw.account, 0),
        index: parseNumber(raw.index, 0),
        ...(raw.hrp ? { hrp: raw.hrp } : {}),
      };
      try {
        const data = await request("/wallet/address", { method: "POST", body: payload });
        setWalletResult(data);
      } catch (error) {
        setWalletResult(error.message, true);
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
        seed_mode: raw.seed_mode || "bip39",
        account: parseNumber(raw.account, 0),
        index: parseNumber(raw.index, 0),
      };
      try {
        const balance = await request("/wallet/balance", { method: "POST", body: payload });
        if (!balance?.address) {
          setWalletResult(balance);
          return;
        }
        try {
          const withHistory = await historyByAddress(balance.address);
          setWalletResult(withHistory);
        } catch (historyError) {
          setWalletResult({
            balance,
            tx_history: [],
            history_error: historyError.message,
          });
        }
      } catch (error) {
        setWalletResult(error.message, true);
      }
    });

  document
    .getElementById("walletBalanceAddressForm")
    .addEventListener("submit", async (event) => {
      event.preventDefault();
      const raw = serializeForm(event.currentTarget);
      const payload = {
        address: raw.address,
      };
      try {
        const withHistory = await historyByAddress(payload.address);
        setWalletResult(withHistory);
      } catch (error) {
        try {
          const balance = await request("/wallet/balance-by-address", {
            method: "POST",
            body: payload,
          });
          setWalletResult({
            balance,
            tx_history: [],
            history_error: error.message,
          });
        } catch (fallbackError) {
          setWalletResult(fallbackError.message, true);
        }
      }
    });

  document.getElementById("walletSendForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const raw = serializeForm(event.currentTarget);
    const payload = {
      mnemonic: raw.mnemonic,
      passphrase: raw.passphrase || "",
      seed_mode: raw.seed_mode || "bip39",
      to: raw.to,
      amount: parseNumber(raw.amount, 0),
      fee: parseNumber(raw.fee, 1),
      account: parseNumber(raw.account, 0),
      index: parseNumber(raw.index, 0),
    };
    try {
      const data = await request("/wallet/send", { method: "POST", body: payload });
      setWalletResult(data);
      await refreshDashboard();
    } catch (error) {
      setWalletResult(error.message, true);
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
      setWalletResult(data);
    } catch (error) {
      setWalletResult(error.message, true);
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
      setWalletResult(data);
    } catch (error) {
      setWalletResult(error.message, true);
    }
  });
}

function initEndpointControls() {
  apiBaseInput.value = state.apiBase;

  saveEndpointBtn.addEventListener("click", async () => {
    state.apiBase = apiBaseInput.value.trim().replace(/\/$/, "");
    localStorage.setItem("scam.console.apiBase", state.apiBase);
    await refreshDashboard();
    startLiveStream();
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
  startLiveStream();
  startSystemClock();
  setInterval(() => {
    refreshDashboard().catch((error) => {
      setResult(mempoolOut, `Auto refresh failed: ${error.message}`, true);
    });
  }, DASHBOARD_POLL_INTERVAL_MS);
  window.addEventListener("beforeunload", () => closeLiveStream());
}

bootstrap();
