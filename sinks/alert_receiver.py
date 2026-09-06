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
  /* Instrument, not web page. The palette is a spectrum-analyser display:
     a near-black enclosure, a faint graticule, and a cold-to-hot ramp for
     signal strength -- the convention SDR waterfalls already use. Signals we
     recognise sit on that ramp; anything unaccounted breaks it and goes red. */
  :root {
    --enclosure:  #070b10;
    --panel:      #0b1219;
    --graticule:  #16222e;
    --rule:       #1c2836;
    --ink:        #e6edf3;
    --ink-dim:    #6b8299;
    --ink-faint:  #3f5568;

    --cold:       #2e6ba8;
    --mid:        #4fc3e8;
    --hot:        #a8f0ff;

    --quiet:      #3dd9a4;
    --attention:  #f0b429;
    --alarm:      #ff3b30;
    --alarm-core: #ffd5d2;
  }

  * { box-sizing: border-box; }

  body {
    margin: 0; min-height: 100vh;
    display: flex; flex-direction: column;
    background: var(--enclosure);
    color: var(--ink);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-variant-numeric: tabular-nums;
    -webkit-font-smoothing: antialiased;
  }

  /* --- header ------------------------------------------------------- */
  header {
    display: flex; align-items: center; gap: 24px;
    padding: 14px 26px; border-bottom: 1px solid var(--rule);
    background: var(--panel);
  }
  .wordmark {
    font-size: 13px; font-weight: 600; color: var(--ink-dim);
    letter-spacing: 0.06em;
  }

  /* An annunciator tile, the way a control room signals a fault: dark and
     inert until something is wrong, then lit. */
  .annunciator {
    display: inline-flex; align-items: center; gap: 11px;
    padding: 9px 18px; border-radius: 2px;
    border: 1px solid var(--rule); background: #0a1017;
    font-size: 26px; font-weight: 500; letter-spacing: -0.01em;
    transition: background 200ms, border-color 200ms, box-shadow 200ms;
  }
  .annunciator .lamp {
    width: 9px; height: 9px; border-radius: 50%;
    background: var(--ink-faint); flex: none;
  }
  .annunciator.quiet { color: var(--quiet); border-color: #14372c; }
  .annunciator.quiet .lamp { background: var(--quiet); box-shadow: 0 0 10px var(--quiet); }
  .annunciator.alarm {
    color: var(--alarm-core); border-color: #4a1512; background: #170a0a;
    box-shadow: inset 0 0 40px rgba(255,59,48,.14);
  }
  .annunciator.alarm .lamp { background: var(--alarm); box-shadow: 0 0 14px var(--alarm); }
  .annunciator.attention { color: var(--attention); border-color: #3d2f0d; }
  .annunciator.attention .lamp { background: var(--attention); box-shadow: 0 0 10px var(--attention); }
  .annunciator.offline { color: var(--ink-dim); }

  .census {
    margin-left: auto; text-align: right;
    font-size: 12px; color: var(--ink-dim); line-height: 1.7;
  }

  /* --- lanes -------------------------------------------------------- */
  .lanes {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(440px, 1fr));
    gap: 1px; background: var(--rule);
  }
  .lane { background: var(--enclosure); padding: 18px 26px 20px; }
  .lane-head {
    display: flex; align-items: baseline; gap: 11px;
    flex-wrap: wrap; margin-bottom: 14px;
  }
  .lane-title { font-size: 15px; font-weight: 600; white-space: nowrap; }
  .lane-sub { font-size: 12px; color: var(--ink-faint); white-space: nowrap; }
  .lane-condition {
    margin-left: auto; font-size: 12px; font-weight: 500; white-space: nowrap;
    display: inline-flex; align-items: center; gap: 7px;
  }
  .lane-condition .lamp { width: 6px; height: 6px; border-radius: 50%; }
  .lane-condition.quiet { color: var(--quiet); }
  .lane-condition.quiet .lamp { background: var(--quiet); box-shadow: 0 0 7px var(--quiet); }
  .lane-condition.alarm { color: var(--alarm); }
  .lane-condition.alarm .lamp { background: var(--alarm); box-shadow: 0 0 9px var(--alarm); }
  .lane-condition.offline { color: var(--ink-faint); }
  .lane-condition.offline .lamp { background: var(--ink-faint); }

  /* --- the instrument face ------------------------------------------ */
  .scope {
    position: relative; background: var(--panel);
    border: 1px solid var(--rule); border-radius: 2px; padding: 8px 8px 4px;
  }
  .spectrum { width: 100%; height: 178px; display: block; }
  .grat        { stroke: var(--graticule); stroke-width: 1; }
  .grat-major  { stroke: var(--rule); stroke-width: 1; }
  .grat-label  { fill: var(--ink-faint); font-size: 9px; }
  .trace-cap   { stroke: none; }

  .axis {
    display: flex; justify-content: space-between;
    font-size: 11px; color: var(--ink-faint); margin-top: 6px;
    padding: 0 2px;
  }
  .axis-span { color: var(--graticule); }

  /* --- readouts ----------------------------------------------------- */
  .readout { margin-top: 14px; }
  .carrier {
    display: flex; align-items: baseline; gap: 14px;
    padding: 6px 0; border-bottom: 1px solid var(--rule);
  }
  .carrier:last-child { border-bottom: none; }
  .freq { font-size: 26px; font-weight: 300; letter-spacing: -0.01em; }
  .freq.unknown { color: var(--alarm-core); font-weight: 400; }
  .ppm { font-size: 14px; color: var(--ink-dim); }
  .tag { margin-left: auto; font-size: 11px; color: var(--ink-faint); }
  .tag.unknown { color: var(--alarm); font-weight: 600; }

  .sessions { width: 100%; border-collapse: collapse; font-size: 13px; }
  .sessions td { padding: 7px 0 5px; border-bottom: 1px solid var(--rule); }
  .sessions td.net { color: var(--ink-faint); font-size: 12px; }
  .sessions td.bytes { text-align: right; color: var(--ink-dim); }
  .sessions tr.flagged td { color: var(--alarm); }

  /* Session size drawn to scale. A firmware pull is an order of magnitude
     larger than a heartbeat, and that is one of the four things the detector
     watches -- worth seeing rather than reading. */
  .vol { padding-top: 0 !important; border-bottom: none !important; }
  .vol-track { height: 3px; background: var(--graticule); border-radius: 2px; }
  .vol-fill { height: 3px; border-radius: 2px; background: var(--cold); }
  tr.flagged .vol-fill { background: var(--alarm); }

  .summary { margin-top: 12px; font-size: 12px; color: var(--ink-faint); }
  .empty { color: var(--ink-faint); font-size: 13px; padding: 24px 0; }
  .lane-body.stale { opacity: 0.28; filter: saturate(0.25); }

  /* --- alerts ------------------------------------------------------- */
  .alerts {
    border-top: 1px solid var(--rule); padding: 14px 26px 22px;
    flex: 1; background: var(--panel);
  }
  .alerts h2 {
    font-size: 12px; font-weight: 600; color: var(--ink-faint);
    margin: 0 0 10px; letter-spacing: 0.04em;
  }
  .alert-row {
    display: flex; align-items: baseline; gap: 16px;
    padding: 9px 0; border-bottom: 1px solid var(--rule); font-size: 14px;
  }
  .alert-time { color: var(--ink-faint); font-size: 12px; width: 66px; flex: none; }
  .alert-sev { width: 66px; flex: none; font-weight: 600; font-size: 12px; }
  .alert-sev.critical, .alert-sev.high { color: var(--alarm); }
  .alert-sev.medium { color: var(--attention); }
  .alert-sev.low, .alert-sev.info { color: var(--ink-dim); }
  .alert-what { font-weight: 500; width: 190px; flex: none; }
  .alert-detail { color: var(--ink-dim); font-size: 13px; }

  @keyframes arrive {
    from { opacity: 0; background: rgba(255,59,48,.12); }
  }
  .alert-row.new { animation: arrive 500ms ease-out; }
  @media (prefers-reduced-motion: reduce) { .alert-row.new { animation: none; } }
</style>
</head>
<body>
  <header>
    <span class="wordmark">GridHawk</span>
    <span class="annunciator quiet" id="annunciator">
      <span class="lamp"></span><span id="headline">Starting</span>
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
const TRAIL_LENGTH = 18;          // sweeps of persistence kept behind the trace
let seenAlerts = new Set();
let trail = [];                   // recent carrier snapshots, newest last

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function conditionWord(c) {
  return { quiet: "Clear", alarm: "Unaccounted emitter",
           offline: "Not reporting", attention: "Degraded" }[c] || c;
}

/* Signal strength maps onto a cold-to-hot ramp, the convention SDR waterfall
   displays already use. Anything unaccounted leaves the ramp entirely. */
function traceColour(overFloorDb, known) {
  if (!known) return "#ff3b30";
  const t = Math.max(0, Math.min(1, (overFloorDb || 0) / 45));
  const stops = [[46,107,168], [79,195,232], [168,240,255]];
  const i = t < 0.5 ? 0 : 1;
  const f = t < 0.5 ? t * 2 : (t - 0.5) * 2;
  const c = stops[i].map((v, k) => Math.round(v + (stops[i+1][k] - v) * f));
  return `rgb(${c[0]},${c[1]},${c[2]})`;
}

function spectrumWindow(carriers, low, high) {
  if (!carriers.length) return [low, high];
  const freqs = carriers.map(c => c.freq_hz);
  const lo = Math.min(...freqs), hi = Math.max(...freqs);
  const centre = (lo + hi) / 2;
  const width = Math.max(6000, (hi - lo) * 4);
  return [centre - width / 2, centre + width / 2];
}

/* The instrument face: a calibrated graticule, recent sweeps fading behind the
   current one, and the live trace on top. Persistence is not decoration -- it
   is how thermal drift becomes visible. A carrier that is warming up leaves a
   trail; a stable one draws a single clean line. */
function spectrum(detail) {
  const carriers = detail.carriers || [];
  const [low, high] = spectrumWindow(carriers, detail.low_hz || 0, detail.high_hz || 1);
  const W = 1000, H = 178, L = 34, R = 8, T = 10, B = 22;
  const plotW = W - L - R, plotH = H - T - B, base = T + plotH;

  let svg = `<svg class="spectrum" viewBox="0 0 ${W} ${H}"
                  preserveAspectRatio="none" role="img"
                  aria-label="${carriers.length} carriers on a calibrated spectrum">`;

  // graticule: 10 vertical divisions, 5 horizontal, labelled in dB over floor
  for (let i = 0; i <= 10; i++) {
    const x = L + (plotW / 10) * i;
    svg += `<line class="${i % 5 === 0 ? "grat-major" : "grat"}"
                  x1="${x}" y1="${T}" x2="${x}" y2="${base}"/>`;
  }
  for (let i = 0; i <= 5; i++) {
    const y = T + (plotH / 5) * i;
    const db = 45 - i * 9;
    svg += `<line class="${i === 5 ? "grat-major" : "grat"}"
                  x1="${L}" y1="${y}" x2="${W - R}" y2="${y}"/>`;
    svg += `<text class="grat-label" x="${L - 6}" y="${y + 3}"
                  text-anchor="end">${db}</text>`;
  }
  svg += `<text class="grat-label" x="4" y="${T + 4}">dB</text>`;

  const plot = (list, opacity, widthPx) => {
    let out = "";
    for (const c of list) {
      const x = L + ((c.freq_hz - low) / (high - low)) * plotW;
      if (x < L || x > W - R) continue;
      const over = Math.max(0, Math.min(1, (c.over_floor_db || 0) / 45));
      const y = base - Math.max(6, over * plotH);
      const colour = traceColour(c.over_floor_db, c.known);
      out += `<line x1="${x.toFixed(1)}" y1="${base}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}"
                    stroke="${colour}" stroke-width="${widthPx}" opacity="${opacity}"/>`;
      if (opacity === 1) {
        out += `<circle class="trace-cap" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}"
                        r="4.5" fill="${colour}"/>`;
      }
    }
    return out;
  };

  // older sweeps first, so the live trace draws over them
  trail.forEach((snapshot, index) => {
    const age = (index + 1) / (trail.length + 1);
    svg += plot(snapshot, (age * 0.30).toFixed(3), 1.5);
  });
  svg += plot(carriers, 1, 3.5);
  svg += `</svg>`;

  const mhz = hz => (hz / 1e6).toFixed(4);
  svg += `<div class="axis">
            <span>${mhz(low)} MHz</span>
            <span class="axis-span">${((high - low) / 1000).toFixed(1)} kHz span</span>
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
  html += `<div class="readout">`;
  for (const c of carriers) {
    const u = c.known ? "" : " unknown";
    html += `<div class="carrier">
      <span class="freq${u}">${(c.freq_hz / 1e6).toFixed(6)}</span>
      <span class="ppm">${c.ppm >= 0 ? "+" : ""}${Number(c.ppm).toFixed(2)} ppm</span>
      <span class="tag${u}">${c.known ? "baselined" : "unaccounted"}</span>
    </div>`;
  }
  if (!carriers.length) html += `<div class="empty">Band clear. No carriers above the floor.</div>`;
  html += `</div>`;

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

  const shown = sessions.slice(0, 9);
  const largest = Math.max(...shown.map(s => s.bytes), 1);

  let html = `<table class="sessions">`;
  for (const s of shown) {
    const width = Math.max(1, (s.bytes / largest) * 100);
    html += `<tr class="${s.allowed ? "" : "flagged"}">
      <td>${esc(s.dst)}</td>
      <td class="net">${esc(s.asn_name)} ${esc(s.cc)}</td>
      <td class="bytes">${Number(s.bytes).toLocaleString()} B</td>
    </tr>
    <tr class="${s.allowed ? "" : "flagged"}">
      <td class="vol" colspan="3">
        <div class="vol-track"><div class="vol-fill" style="width:${width.toFixed(1)}%"></div></div>
      </td>
    </tr>`;
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
  document.getElementById("annunciator").className = "annunciator " + state.condition;

  const reporting = state.lanes.filter(l => l.condition !== "offline").length;
  document.getElementById("census").innerHTML =
    `${reporting} of ${state.lanes.length} layers reporting<br>${state.alert_count} alerts`;

  document.getElementById("lanes").innerHTML = state.lanes.map(lane => `
    <section class="lane">
      <div class="lane-head">
        <span class="lane-title">${esc(lane.title)}</span>
        <span class="lane-sub">${esc(lane.subtitle)}</span>
        <span class="lane-condition ${lane.condition}">
          <span class="lamp"></span>${conditionWord(lane.condition)}
        </span>
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
  } catch (e) { /* hold the last good frame rather than blanking the screen */ }
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
