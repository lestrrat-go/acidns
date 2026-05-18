"use strict";

const $ = (id) => document.getElementById(id);

// Mode is fetched from /api/config in init() and stashed here so the
// submit and the field-sync code can branch on it without round-trips.
let UI_MODE = "basic";

// Well-known DoT endpoints → TLS server name. Used to pre-fill the
// TLS-name field when the user picks one of these upstreams with the
// DoT transport. The user can override; we only auto-fill when the
// field is empty.
const WELL_KNOWN_DOT_NAMES = {
  "1.1.1.1": "cloudflare-dns.com",
  "1.0.0.1": "cloudflare-dns.com",
  "8.8.8.8": "dns.google",
  "8.8.4.4": "dns.google",
  "9.9.9.9": "dns.quad9.net",
  "149.112.112.112": "dns.quad9.net",
  "8.26.56.26": "dns.cleanbrowsing.org",
  "94.140.14.14": "dns.adguard-dns.com",
  "94.140.15.15": "dns.adguard-dns.com",
};

function defaultTLSName(upstream) {
  if (!upstream) return "";
  // Strip optional :port. IPv6 in brackets is not in the map so we
  // don't bother parsing those.
  const ip = upstream.replace(/:\d+$/, "");
  return WELL_KNOWN_DOT_NAMES[ip] || "";
}

// Mirror of the server-side wellKnownDoHURLs map. URLs use the IP
// literal as the host because every entry's certificate has that IP
// in its SAN, so the connection reaches the upstream the user picked
// without an interstitial DNS resolution.
const WELL_KNOWN_DOH_URLS = {
  "1.1.1.1": "https://1.1.1.1/dns-query",
  "1.0.0.1": "https://1.0.0.1/dns-query",
  "8.8.8.8": "https://8.8.8.8/dns-query",
  "8.8.4.4": "https://8.8.4.4/dns-query",
  "9.9.9.9": "https://9.9.9.9/dns-query",
  "149.112.112.112": "https://149.112.112.112/dns-query",
};

function defaultDoHURL(upstream) {
  if (!upstream) return "";
  const ip = upstream.replace(/:\d+$/, "");
  return WELL_KNOWN_DOH_URLS[ip] || "";
}

async function init() {
  let cfg;
  try {
    cfg = await fetch("/api/config").then((r) => r.json());
  } catch (e) {
    showError("failed to load /api/config: " + e);
    return;
  }
  UI_MODE = cfg.mode;
  document.body.classList.add("mode-" + cfg.mode);
  const badge = $("mode-badge");
  badge.textContent = cfg.mode;
  badge.classList.add(cfg.mode);

  const qtype = $("qtype");
  for (const t of cfg.qtypes) {
    const opt = document.createElement("option");
    opt.value = t;
    opt.textContent = t;
    if (t === "A") opt.selected = true;
    qtype.appendChild(opt);
  }

  const upstream = $("upstream");
  if (cfg.upstreams.length === 0) {
    const opt = document.createElement("option");
    opt.value = "";
    opt.textContent = "(no configured upstream — pass --web-upstream)";
    opt.disabled = true;
    upstream.appendChild(opt);
  } else {
    for (const u of cfg.upstreams) {
      const opt = document.createElement("option");
      opt.value = u;
      opt.textContent = u;
      upstream.appendChild(opt);
    }
  }

  // The TLS-name and DoH-URL inputs are only meaningful for their
  // respective transports; hide them when irrelevant rather than
  // confusing the user with empty fields. Changing the upstream may
  // re-trigger the well-known defaults and per-transport hints.
  $("transport").addEventListener("change", syncTransportFields);
  const onUpstreamChange = () => {
    maybeFillTLSName();
    maybeFillDoHURL();
    syncDoTHint();
    syncDoHHint();
  };
  $("upstream").addEventListener("change", onUpstreamChange);
  $("upstream-raw").addEventListener("input", onUpstreamChange);
  syncTransportFields();

  $("query-form").addEventListener("submit", onSubmit);
}

function currentUpstream() {
  const raw = $("upstream-raw").value.trim();
  return raw || $("upstream").value || "";
}

// maybeFillTLSName pre-populates the TLS-name field with a known
// server name for the current upstream when the field is empty. It
// runs on transport change and on upstream change. User edits are
// preserved — we never overwrite a non-empty value.
function maybeFillTLSName() {
  if ($("transport").value !== "dot") return;
  const tlsName = $("tls-name");
  if (tlsName.value.trim() !== "") return;
  const guess = defaultTLSName(currentUpstream());
  if (guess) tlsName.value = guess;
}

function syncTransportFields() {
  const t = $("transport").value;
  const isDoT = t === "dot";
  const isDoH = t === "doh";
  $("tls-name-row").hidden = !isDoT;
  $("doh-url-row").hidden = !isDoH;

  // The TLS-name field is optional; the server resolves a sensible
  // default for well-known DoT endpoints and falls back to insecure
  // mode when nothing else applies. Auto-fill still runs so the user
  // sees the actual server name when it's a known endpoint.
  $("tls-name").required = false;
  $("tls-name-label").textContent = isDoT ? "TLS server name (auto)" : "TLS server name";
  if (isDoT) maybeFillTLSName();

  // Basic mode never accepts a free-form DoH URL — the server derives
  // the URL from the upstream IP allow-list. Show the resolved URL
  // for transparency but lock the field so the user can't edit it,
  // and the submit will drop the value.
  const dohURL = $("doh-url");
  dohURL.required = false;
  dohURL.readOnly = isDoH && UI_MODE === "basic";
  if (isDoH) {
    $("doh-url-label").textContent =
      UI_MODE === "basic" ? "DoH URL (auto, read-only in basic mode)" : "DoH URL (auto)";
    maybeFillDoHURL();
  } else {
    $("doh-url-label").textContent = "DoH URL";
  }

  syncDoTHint();
  syncDoHHint();
}

// maybeFillDoHURL pre-populates the DoH URL field from the well-known
// map. Like the TLS-name path: known-IP → known URL, never overwrites
// a non-empty value.
function maybeFillDoHURL() {
  if ($("transport").value !== "doh") return;
  const dohURL = $("doh-url");
  if (dohURL.value.trim() !== "") return;
  const guess = defaultDoHURL(currentUpstream());
  if (guess) dohURL.value = guess;
}

// syncDoHHint mirrors syncDoTHint for DoH: warn when DoH is selected
// against an upstream the well-known map doesn't cover, so the user
// knows they need to provide an explicit URL (advanced mode) or pick
// a different upstream.
function syncDoHHint() {
  const hint = $("doh-hint");
  if ($("transport").value !== "doh") {
    hint.hidden = true;
    return;
  }
  const up = currentUpstream();
  const ip = up.replace(/:\d+$/, "");
  if (ip && WELL_KNOWN_DOH_URLS[ip]) {
    hint.hidden = true;
    return;
  }
  hint.textContent =
    "Heads-up: this upstream isn't a known DoH server. " +
    "Provide a DoH URL above or pick a known DoH resolver such as 1.1.1.1, 8.8.8.8, or 9.9.9.9.";
  hint.hidden = false;
}

// syncDoTHint shows a warning under the transport selector when DoT is
// chosen against an upstream that we don't know to support DoT. The
// dropdown is populated from /etc/resolv.conf and --web-upstream, which
// are typically port-53 caching resolvers (e.g. Tailscale's
// 100.100.100.100) — those usually don't expose DoT, and the resulting
// timeout is otherwise opaque. The hint points the user at known
// public DoT resolvers.
function syncDoTHint() {
  const hint = $("dot-hint");
  if ($("transport").value !== "dot") {
    hint.hidden = true;
    return;
  }
  const up = currentUpstream();
  const ip = up.replace(/:\d+$/, "");
  if (ip && WELL_KNOWN_DOT_NAMES[ip]) {
    hint.hidden = true;
    return;
  }
  hint.textContent =
    "Heads-up: this upstream isn't a known DoT server. " +
    "If the query times out, it likely doesn't speak DoT on port 853. " +
    "Try a public DoT resolver such as 1.1.1.1, 8.8.8.8, or 9.9.9.9.";
  hint.hidden = false;
}

async function onSubmit(ev) {
  ev.preventDefault();
  const btn = ev.target.querySelector("button[type=submit]");
  btn.disabled = true;
  $("status").textContent = "querying...";
  $("error").hidden = true;
  $("result").hidden = true;

  const body = {
    name: $("qname").value.trim(),
    qtype: $("qtype").value,
    qtype_raw: $("qtype-raw").value.trim(),
    upstream: $("upstream").value,
    upstream_raw: $("upstream-raw").value.trim(),
    transport: $("transport").value,
    tls_name: $("tls-name").value.trim(),
    // Basic mode rejects free-form DoH URLs; the field is read-only
    // and displays the server-derived URL only. Drop it from the
    // payload so the server stays the sole authority on which URL
    // gets used.
    doh_url: UI_MODE === "basic" ? "" : $("doh-url").value.trim(),
    do: $("flag-do").checked,
    cd: $("flag-cd").checked,
    rd: $("flag-rd").checked,
    edns: $("flag-edns").checked,
    show_raw: $("flag-raw").checked,
  };

  try {
    const resp = await fetch("/api/query", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (!resp.ok || data.error) {
      showError(data.error || ("HTTP " + resp.status));
      return;
    }
    renderResult(data);
  } catch (e) {
    showError(String(e));
  } finally {
    btn.disabled = false;
    $("status").textContent = "";
  }
}

function renderResult(data) {
  $("r-rcode").textContent = data.rcode || "";
  $("r-server").textContent = data.server || "—";
  $("r-elapsed").textContent = (data.elapsed_ms ?? 0) + " ms";

  $("r-request").textContent = formatMessage(data.request);
  $("r-response").textContent = formatMessage(data.response);

  const reqHTTPShown = !!data.http_request;
  const respHTTPShown = !!data.http_response;
  document.querySelector("#req-panel .http").hidden = !reqHTTPShown;
  document.querySelector("#resp-panel .http").hidden = !respHTTPShown;
  if (reqHTTPShown) $("r-http-request").textContent = data.http_request;
  if (respHTTPShown) $("r-http-response").textContent = data.http_response;

  const reqRawShown = !!data.request_hex;
  const respRawShown = !!data.response_hex;
  document.querySelector("#req-panel .raw").hidden = !reqRawShown;
  document.querySelector("#resp-panel .raw").hidden = !respRawShown;
  if (reqRawShown) $("r-request-hex").textContent = formatHex(data.request_hex);
  if (respRawShown) $("r-response-hex").textContent = formatHex(data.response_hex);

  $("result").hidden = false;
}

function formatMessage(m) {
  if (!m) return "(none)";
  const lines = [];
  lines.push(
    ";; ->>HEADER<<- opcode: " + m.opcode +
    ", status: " + m.rcode +
    ", id: " + m.id
  );
  lines.push(";; flags: " + (m.flags || []).join(" ") + "; " + m.counts);

  if (m.edns && m.edns.length) {
    lines.push("");
    lines.push(";; OPT PSEUDOSECTION:");
    for (const line of m.edns) lines.push(line);
  }
  if (m.question && m.question.length) {
    lines.push("");
    lines.push(";; QUESTION SECTION:");
    for (const line of m.question) lines.push(line);
  }
  if (m.answer && m.answer.length) {
    lines.push("");
    lines.push(";; ANSWER SECTION:");
    for (const line of m.answer) lines.push(line);
  }
  if (m.authority && m.authority.length) {
    lines.push("");
    lines.push(";; AUTHORITY SECTION:");
    for (const line of m.authority) lines.push(line);
  }
  if (m.additional && m.additional.length) {
    lines.push("");
    lines.push(";; ADDITIONAL SECTION:");
    for (const line of m.additional) lines.push(line);
  }
  return lines.join("\n");
}

function formatHex(s) {
  if (!s) return "(empty)";
  const groups = [];
  for (let i = 0; i < s.length; i += 32) {
    groups.push(s.slice(i, i + 32).replace(/(..)(?=.)/g, "$1 "));
  }
  return groups.join("\n");
}

function showError(msg) {
  $("r-error").textContent = msg;
  $("error").hidden = false;
}

init();
