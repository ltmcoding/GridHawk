"""Where alerts and monitor heartbeats arrive, and the screen that shows them.

Run this on the machine with the projector. Monitors post two kinds of message:

    POST /alert    something is wrong, with the evidence
    POST /status   a heartbeat: still watching, here is what I currently see

The second matters as much as the first. A dashboard that only hears about
anomalies shows an empty screen when everything is fine -- which looks exactly
like a dashboard whose monitors have died. The heartbeat is what lets the
screen say "watching, nothing wrong" and mean it.

Deliberately self-contained: no fonts, scripts or styles are fetched from
anywhere. A venue that blocks a font CDN would otherwise leave you presenting
an unstyled page.
"""

from __future__ import annotations

import argparse
import html
import json
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


POLL_INTERVAL_MS = 1000
MAX_ALERTS_RETAINED = 200

# A monitor that has not checked in for this long is treated as offline rather
# than quiet. Both are silence; only one of them is good news.
HEARTBEAT_STALE_S = 25.0

# How the two collectors are presented. Order here is the order on screen.
LANES = [
    ("rf", "RF spectrum", "Enclosure emissions"),
    ("tls_egress", "Network egress", "Outbound connections"),
]

received_alerts: list[dict] = []
monitor_status: dict[str, dict] = {}


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------

def _lane_state(source: str) -> dict:
    """Current condition of one collector: offline, alarm, or quiet."""
    status = monitor_status.get(source)
    if status is None:
        return {"condition": "offline", "detail": {}, "age": None}

    age = time.time() - status.get("ts", 0)
    if age > HEARTBEAT_STALE_S:
        return {"condition": "offline", "detail": status.get("detail", {}), "age": age}

    condition = "alarm" if status.get("state") == "alert" else "quiet"
    return {"condition": condition, "detail": status.get("detail", {}), "age": age}


def _overall_state() -> tuple[str, str]:
    """One word for the header, and the condition driving it."""
    conditions = []
    for source, _title, _sub in LANES:
        conditions.append(_lane_state(source)["condition"])

    if "alarm" in conditions:
        return "Unaccounted emitter", "alarm"
    if all(c == "offline" for c in conditions):
        return "No monitors reporting", "offline"
    if "offline" in conditions:
        return "Partial coverage", "attention"
    return "Secure", "quiet"


def _snapshot() -> dict:
    headline, condition = _overall_state()
    lanes = []
    for source, title, subtitle in LANES:
        state = _lane_state(source)
        lanes.append({
            "source": source,
            "title": title,
            "subtitle": subtitle,
            "condition": state["condition"],
            "detail": state["detail"],
        })
    return {
        "headline": headline,
        "condition": condition,
        "lanes": lanes,
        "alerts": list(reversed(received_alerts))[:40],
        "alert_count": len(received_alerts),
    }


# --------------------------------------------------------------------------
# The page. Styles and script are inline so nothing is fetched at load.
# --------------------------------------------------------------------------

PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GridHawk</title>
<style>
  /* Restraint is the idea. One accent, used only where it carries meaning:
     everything the system recognises is rendered in near-white, and only the
     thing it cannot account for takes colour. Space and type scale do the rest
     of the work, so the page reads composed rather than busy. */
  :root {
    --ground:   #0f1215;
    --lift:     rgba(255,255,255,0.022);
    --lift-2:   rgba(255,255,255,0.04);
    --hairline: rgba(255,255,255,0.07);

    --ink:      #f2f4f5;
    --ink-mid:  #949ca3;
    --ink-dim:  #5d666d;

    --signal:   #e8eaed;
    --accent:   #ff5b49;
    --accent-d: rgba(255,91,73,0.16);
    --ok:       #5fd9a8;
    --warn:     #f5c451;
  }

  * { box-sizing: border-box; }

  body {
    margin: 0; min-height: 100vh;
    display: flex; flex-direction: column;
    background: var(--ground);
    color: var(--ink);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-variant-numeric: tabular-nums;
    -webkit-font-smoothing: antialiased;
    letter-spacing: -0.006em;
  }

  /* --- header ------------------------------------------------------- */
  header {
    display: flex; align-items: center; gap: 22px;
    padding: 34px 48px 30px;
  }
  .wordmark { font-size: 13px; font-weight: 600; color: var(--ink-dim); }

  .state { display: flex; align-items: center; gap: 14px; }
  .lamp {
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--ink-dim); flex: none;
  }
  .state.quiet .lamp { background: var(--ok);     box-shadow: 0 0 0 5px rgba(95,217,168,.12); }
  .state.alarm .lamp { background: var(--accent); box-shadow: 0 0 0 5px var(--accent-d); }
  .state.attention .lamp { background: var(--warn); box-shadow: 0 0 0 5px rgba(245,196,81,.12); }

  .headline { font-size: 34px; font-weight: 300; letter-spacing: -0.025em; }
  .state.alarm .headline { color: var(--accent); }
  .state.offline .headline { color: var(--ink-mid); }

  .census {
    margin-left: auto; text-align: right;
    font-size: 12px; color: var(--ink-dim); line-height: 1.8;
  }

  /* --- lanes -------------------------------------------------------- */
  .lanes {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(460px, 1fr));
    gap: 20px; padding: 0 48px 40px;
  }
  .lane { min-width: 0; overflow: hidden; }
  .lane-head {
    display: flex; align-items: baseline; gap: 12px;
    flex-wrap: wrap; margin-bottom: 20px;
  }
  .lane-title { font-size: 14px; font-weight: 600; white-space: nowrap; }
  .lane-sub { font-size: 13px; color: var(--ink-dim); white-space: nowrap; }
  .lane-status {
    margin-left: auto; font-size: 12px; font-weight: 500;
    color: var(--ink-mid); white-space: nowrap;
  }
  .lane-status.alarm { color: var(--accent); }

  /* --- the trace ---------------------------------------------------- */
  .scope {
    background: var(--lift); border-radius: 14px;
    padding: 20px 22px 14px; margin-bottom: 26px;
  }
  .spectrum { width: 100%; height: 190px; display: block; }
  .ref { stroke: rgba(255,255,255,0.05); stroke-width: 1; }
  .axis {
    display: flex; justify-content: space-between;
    font-size: 11px; color: var(--ink-dim); margin-top: 10px;
  }

  /* --- readouts ----------------------------------------------------- */
  .carrier { padding: 14px 0; border-bottom: 1px solid var(--hairline); }
  .carrier:last-child { border-bottom: none; }
  .carrier-top { display: flex; align-items: baseline; gap: 16px; }
  .freq {
    font-size: 52px; font-weight: 200; letter-spacing: -0.035em;
    line-height: 1; color: var(--signal);
  }
  .freq.unknown { color: var(--accent); }
  .ppm { font-size: 15px; color: var(--ink-mid); }
  .tag { margin-left: auto; font-size: 12px; color: var(--ink-dim); }
  .tag.unknown { color: var(--accent); font-weight: 600; }

  .sessions {
    width: 100%; border-collapse: collapse; font-size: 14px;
    table-layout: fixed;
  }
  .sessions td { padding: 13px 0 6px; overflow: hidden; text-overflow: ellipsis; }
  .sessions td.dst { width: 42%; white-space: nowrap; }
  .sessions td.net {
    color: var(--ink-dim); font-size: 13px; width: 38%;
    white-space: nowrap;
  }
  .sessions td.bytes { text-align: right; color: var(--ink-mid); width: 20%; }
  .sessions tr.flagged td { color: var(--accent); }
  .vol { padding: 0 0 12px !important; border-bottom: 1px solid var(--hairline); }
  .vol-track { height: 2px; background: var(--lift-2); border-radius: 2px; }
  .vol-fill { height: 2px; border-radius: 2px; background: var(--ink-dim); }
  tr.flagged .vol-fill { background: var(--accent); }

  .summary { margin-top: 18px; font-size: 13px; color: var(--ink-dim); }
  .empty { color: var(--ink-dim); font-size: 14px; padding: 40px 0; }
  .lane-body.stale { opacity: 0.3; }

  /* --- alerts ------------------------------------------------------- */
  .alerts { padding: 28px 48px 44px; border-top: 1px solid var(--hairline); flex: 1; }
  .alerts h2 { font-size: 13px; font-weight: 600; color: var(--ink-dim); margin: 0 0 6px; }
  .alert-row {
    display: flex; align-items: baseline; gap: 20px;
    padding: 16px 0; border-bottom: 1px solid var(--hairline); font-size: 15px;
  }
  .alert-row:last-child { border-bottom: none; }
  .alert-time { color: var(--ink-dim); font-size: 13px; width: 70px; flex: none; }
  .alert-sev { width: 70px; flex: none; font-weight: 600; font-size: 13px; color: var(--ink-mid); }
  .alert-sev.critical, .alert-sev.high { color: var(--accent); }
  .alert-sev.medium { color: var(--warn); }
  .alert-what { font-weight: 500; width: 210px; flex: none; }
  .alert-detail { color: var(--ink-mid); font-size: 14px; }

  @keyframes arrive { from { opacity: 0; transform: translateY(-4px); } }
  .alert-row.new { animation: arrive 420ms cubic-bezier(.2,.7,.3,1); }
  @media (prefers-reduced-motion: reduce) { .alert-row.new { animation: none; } }

  @media (max-width: 720px) {
    header, .lanes, .alerts { padding-left: 24px; padding-right: 24px; }
    .freq { font-size: 40px; }
  }
</style>
</head>
<body>
  <header>
    <span class="wordmark">GridHawk</span>
    <span class="state quiet" id="state">
      <span class="lamp"></span><span class="headline" id="headline">Starting</span>
    </span>
    <div class="census" id="census"></div>
  </header>
  <div class="lanes" id="lanes"></div>
  <div class="alerts">
    <h2>Alerts</h2>
    <div id="alert-list"></div>
  </div>

<script>
const POLL_MS = __POLL_MS__;
const TRAIL_LENGTH = 14;
let seenAlerts = new Set();
let trail = [];

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function statusWord(c) {
  return { quiet: "Clear", alarm: "Unaccounted emitter",
           offline: "Not reporting", attention: "Degraded" }[c] || c;
}

function spectrumWindow(carriers, low, high) {
  if (!carriers.length) return [low, high];
  const freqs = carriers.map(c => c.freq_hz);
  const lo = Math.min(...freqs), hi = Math.max(...freqs);
  const centre = (lo + hi) / 2;
  return [centre - Math.max(6000, (hi - lo) * 4) / 2,
          centre + Math.max(6000, (hi - lo) * 4) / 2];
}

/* A filled peak with a soft falloff rather than a hard spike. Real signals
   have skirts, so this is both truer to the measurement and quieter to look
   at than a forest of lines. Recent sweeps sit behind at low opacity, which
   is how thermal drift becomes visible: a warming transmitter smears, a
   settled one draws one clean peak. */
function peakPath(x, y, base, halfWidth) {
  const w = halfWidth;
  return `M ${(x - w).toFixed(1)} ${base}
          C ${(x - w * 0.45).toFixed(1)} ${base}
            ${(x - w * 0.28).toFixed(1)} ${y.toFixed(1)}
            ${x.toFixed(1)} ${y.toFixed(1)}
          C ${(x + w * 0.28).toFixed(1)} ${y.toFixed(1)}
            ${(x + w * 0.45).toFixed(1)} ${base}
            ${(x + w).toFixed(1)} ${base} Z`;
}

function spectrum(detail) {
  const carriers = detail.carriers || [];
  const [low, high] = spectrumWindow(carriers, detail.low_hz || 0, detail.high_hz || 1);
  const W = 1000, H = 190, T = 12, B = 8;
  const plotH = H - T - B, base = T + plotH;

  let svg = `<svg class="spectrum" viewBox="0 0 ${W} ${H}"
                  preserveAspectRatio="none" role="img"
                  aria-label="${carriers.length} carriers detected">
    <defs>
      <linearGradient id="fillKnown" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%"   stop-color="#e8eaed" stop-opacity="0.30"/>
        <stop offset="100%" stop-color="#e8eaed" stop-opacity="0"/>
      </linearGradient>
      <linearGradient id="fillUnknown" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%"   stop-color="#ff5b49" stop-opacity="0.42"/>
        <stop offset="100%" stop-color="#ff5b49" stop-opacity="0"/>
      </linearGradient>
    </defs>`;

  // three faint reference lines, not a full grid
  for (let i = 1; i <= 3; i++) {
    const y = T + (plotH / 4) * i;
    svg += `<line class="ref" x1="0" y1="${y}" x2="${W}" y2="${y}"/>`;
  }
  svg += `<line class="ref" x1="0" y1="${base}" x2="${W}" y2="${base}"/>`;

  const draw = (list, opacity, stroked) => {
    let out = "";
    for (const c of list) {
      const x = ((c.freq_hz - low) / (high - low)) * W;
      if (x < -40 || x > W + 40) continue;
      const over = Math.max(0, Math.min(1, (c.over_floor_db || 0) / 45));
      const y = base - Math.max(10, over * plotH);
      const fill = c.known ? "url(#fillKnown)" : "url(#fillUnknown)";
      const line = c.known ? "#e8eaed" : "#ff5b49";
      const path = peakPath(x, y, base, 46);
      out += `<path d="${path}" fill="${fill}" opacity="${opacity}"/>`;
      if (stroked) {
        out += `<path d="${path}" fill="none" stroke="${line}"
                      stroke-width="1.6" stroke-linejoin="round" opacity="${opacity}"/>`;
      }
    }
    return out;
  };

  trail.forEach((snapshot, index) => {
    const age = (index + 1) / (trail.length + 1);
    svg += draw(snapshot, (age * 0.22).toFixed(3), false);
  });
  svg += draw(carriers, 1, true);
  svg += `</svg>`;

  const mhz = hz => (hz / 1e6).toFixed(4);
  svg += `<div class="axis">
            <span>${mhz(low)} MHz</span>
            <span>${((high - low) / 1000).toFixed(1)} kHz</span>
            <span>${mhz(high)} MHz</span>
          </div>`;
  return `<div class="scope">${svg}</div>`;
}

function rfLane(lane) {
  const d = lane.detail || {};
  const carriers = d.carriers || [];
  if (!carriers.length && lane.condition === "offline") {
    return `<div class="empty">No sweeps received. Start the RF monitor with --alert-url.</div>`;
  }

  let html = spectrum(d);
  for (const c of carriers) {
    const u = c.known ? "" : " unknown";
    html += `<div class="carrier"><div class="carrier-top">
      <span class="freq${u}">${(c.freq_hz / 1e6).toFixed(6)}</span>
      <span class="ppm">${c.ppm >= 0 ? "+" : ""}${Number(c.ppm).toFixed(2)} ppm</span>
      <span class="tag${u}">${c.known ? "baselined" : "unaccounted"}</span>
    </div></div>`;
  }
  if (!carriers.length) html += `<div class="empty">Band clear. No carriers above the floor.</div>`;

  const bits = [];
  if (d.sweeps) bits.push(`${d.sweeps} sweeps`);
  if (d.separation_hz) bits.push(`${Math.round(d.separation_hz)} Hz apart`);
  if (d.noise_floor_db != null) bits.push(`floor ${Number(d.noise_floor_db).toFixed(1)} dB`);
  if (bits.length) html += `<div class="summary">${esc(bits.join(", "))}</div>`;
  return html;
}

function networkLane(lane) {
  const d = lane.detail || {};
  const sessions = d.sessions || [];
  if (!sessions.length && lane.condition === "offline") {
    return `<div class="empty">No capture windows received. Start the network monitor with --alert-url.</div>`;
  }
  if (!sessions.length) return `<div class="empty">No outbound sessions in this window.</div>`;

  const shown = sessions.slice(0, 8);
  const largest = Math.max(...shown.map(s => s.bytes), 1);
  let html = `<table class="sessions">`;
  for (const s of shown) {
    const width = Math.max(1.5, (s.bytes / largest) * 100);
    const cls = s.allowed ? "" : "flagged";
    html += `<tr class="${cls}">
      <td class="dst">${esc(s.dst)}</td>
      <td class="net">${esc(s.asn_name)} ${esc(s.cc)}</td>
      <td class="bytes">${Number(s.bytes).toLocaleString()} B</td>
    </tr>
    <tr class="${cls}"><td class="vol" colspan="3">
      <div class="vol-track"><div class="vol-fill" style="width:${width.toFixed(1)}%"></div></div>
    </td></tr>`;
  }
  html += `</table>`;
  const flagged = sessions.filter(s => !s.allowed).length;
  html += `<div class="summary">${esc(d.windows || 0)} windows, ${
    flagged ? `${flagged} to an unrecognised network`
            : `all ${sessions.length} to authorised networks`}</div>`;
  return html;
}

function render(state) {
  const rf = state.lanes.find(l => l.source === "rf");
  if (rf && rf.condition !== "offline") {
    trail.push((rf.detail.carriers || []).map(c => ({ ...c })));
    while (trail.length > TRAIL_LENGTH) trail.shift();
  }

  document.getElementById("headline").textContent = state.headline;
  document.getElementById("state").className = "state " + state.condition;

  const reporting = state.lanes.filter(l => l.condition !== "offline").length;
  document.getElementById("census").innerHTML =
    `${reporting} of ${state.lanes.length} layers reporting<br>${state.alert_count} alerts`;

  document.getElementById("lanes").innerHTML = state.lanes.map(lane => `
    <section class="lane">
      <div class="lane-head">
        <span class="lane-title">${esc(lane.title)}</span>
        <span class="lane-sub">${esc(lane.subtitle)}</span>
        <span class="lane-status ${lane.condition}">${statusWord(lane.condition)}</span>
      </div>
      <div class="lane-body${lane.condition === "offline" ? " stale" : ""}">
        ${lane.source === "rf" ? rfLane(lane) : networkLane(lane)}
      </div>
    </section>`).join("");

  const list = document.getElementById("alert-list");
  if (!state.alerts.length) {
    list.innerHTML = `<div class="empty">Nothing raised. Both layers are being watched.</div>`;
  } else {
    list.innerHTML = state.alerts.map(a => {
      const isNew = !seenAlerts.has(a.id);
      seenAlerts.add(a.id);
      return `<div class="alert-row${isNew ? " new" : ""}">
        <span class="alert-time">${esc(a.received_at)}</span>
        <span class="alert-sev ${esc(a.severity)}">${esc(a.severity)}</span>
        <span class="alert-what">${esc(a.what)}</span>
        <span class="alert-detail">${esc(a.summary)}</span>
      </div>`;
    }).join("");
  }
}

async function poll() {
  try {
    const r = await fetch("/state.json", { cache: "no-store" });
    render(await r.json());
  } catch (e) { /* hold the last good frame */ }
}
poll();
setInterval(poll, POLL_MS);
</script>
</body></html>
"""


# --------------------------------------------------------------------------
# Turning a Finding into one readable line
# --------------------------------------------------------------------------

WHAT_BY_KIND = {
    "excess_emitter": "Unaccounted emitter",
    "new_asn": "Unknown network",
    "geo_drift": "Unexpected country",
    "tunnel_indicator": "Tunnelled egress",
    "volume_spike": "Oversized transfer",
    "off_cycle_burst": "Off-cycle connection",
    "modbus_write": "Unauthorised register write",
    "attestation_fail": "Firmware attestation failed",
}


def _summarise(alert: dict) -> str:
    """The one line of evidence shown beside an alert.

    Chosen per kind rather than dumping the detail dictionary: on a projector,
    a line of key=value pairs is unreadable, and the useful fact differs by
    what was detected.
    """
    detail = alert.get("detail", {})
    kind = alert.get("kind", "")

    if kind == "excess_emitter" and "freq_hz" in detail:
        parts = [f"{detail['freq_hz'] / 1e6:.6f} MHz"]
        if detail.get("ppm") is not None:
            parts.append(f"{detail['ppm']:+.2f} ppm")
        offset = detail.get("offset_from_nearest_known_hz")
        if offset:
            parts.append(f"{round(offset)} Hz from the baselined radio")
        return ", ".join(parts)

    if kind in ("new_asn", "geo_drift", "tunnel_indicator"):
        parts = [str(detail.get("dst", ""))]
        if detail.get("asn_name"):
            parts.append(f"{detail['asn_name']} ({detail.get('cc', '')})")
        if detail.get("device"):
            parts.append(f"{detail['device']}, {detail.get('capacity_kw', '?')} kW")
        return ", ".join(p for p in parts if p)

    if kind == "volume_spike":
        return f"{detail.get('bytes', 0):,} bytes, {detail.get('factor', '?')}x normal"

    if kind == "off_cycle_burst":
        return (f"{detail.get('interval', '?')}s gap against a "
                f"{detail.get('channel_period', '?')}s cycle")

    return ""


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

class AlertHandler(BaseHTTPRequestHandler):
    """Accepts alerts and heartbeats, and serves the dashboard."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format_string, *args):
        """Silence the request log so the console shows only alerts."""

    def _respond(self, status: int, body: bytes, content_type: str) -> None:
        """Send one complete response."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict | None:
        length = int(self.headers.get("Content-Length", 0))
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            return None

    def do_POST(self):
        """Receive an alert, or a heartbeat from a monitor."""
        payload = self._read_json()
        if payload is None:
            self._respond(400, b'{"error":"invalid json"}', "application/json")
            return

        if self.path.startswith("/status"):
            source = payload.get("source", "unknown")
            payload["ts"] = time.time()      # our clock, not the sender's
            monitor_status[source] = payload
            self._respond(200, b'{"ok":true}', "application/json")
            return

        stamped = dict(payload)
        stamped["received_at"] = datetime.now(timezone.utc).strftime("%H:%M:%S")
        stamped["id"] = f"{time.time():.6f}"
        stamped["what"] = WHAT_BY_KIND.get(payload.get("kind", ""), payload.get("kind", ""))
        stamped["summary"] = _summarise(payload)

        received_alerts.append(stamped)
        while len(received_alerts) > MAX_ALERTS_RETAINED:
            received_alerts.pop(0)

        print(f"[{stamped['received_at']}] {payload.get('severity', '?'):<8} "
              f"{stamped['what']:<28} {stamped['summary']}")

        self._respond(200, b'{"ok":true}', "application/json")

    def do_GET(self):
        """Serve the dashboard, its state, or the raw alert list."""
        if self.path.startswith("/state.json"):
            body = json.dumps(_snapshot()).encode("utf-8")
            self._respond(200, body, "application/json")
            return
        if self.path.startswith("/alerts.json"):
            body = json.dumps(received_alerts).encode("utf-8")
            self._respond(200, body, "application/json")
            return
        page = PAGE.replace("__POLL_MS__", str(POLL_INTERVAL_MS))
        self._respond(200, page.encode("utf-8"), "text/html; charset=utf-8")


def main() -> None:
    """Run the receiver until interrupted."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0",
                        help="0.0.0.0 so monitors elsewhere on the LAN can reach it")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.bind, args.port), AlertHandler)
    print(f"GridHawk dashboard on http://{args.bind}:{args.port}")
    print(f"  monitors post alerts to  /alert")
    print(f"  and heartbeats to        /status")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
