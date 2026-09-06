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
  :root {
    --ground:    #16212b;
    --panel:     #1d2b37;
    --rule:      #2c3e4c;
    --ink:       #dce6ed;
    --ink-dim:   #7e93a3;
    --quiet:     #57c4a8;
    --attention: #ffb020;
    --alarm:     #ff5c5c;
    --known:     #7fb3d5;
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
  }

  /* --- header ------------------------------------------------------- */
  header {
    display: flex; align-items: baseline; gap: 28px;
    padding: 16px 28px; border-bottom: 1px solid var(--rule);
  }
  .wordmark { font-size: 15px; font-weight: 600; letter-spacing: 0.02em; color: var(--ink-dim); }
  .headline { font-size: 40px; font-weight: 600; letter-spacing: -0.02em; line-height: 1; }
  .headline.quiet     { color: var(--quiet); }
  .headline.alarm     { color: var(--alarm); }
  .headline.attention { color: var(--attention); }
  .headline.offline   { color: var(--ink-dim); }
  .census { margin-left: auto; text-align: right; font-size: 13px; color: var(--ink-dim); line-height: 1.6; }

  /* --- lanes -------------------------------------------------------- */
  /* Two lanes wherever there is room for them, one when there is not. A fixed
     breakpoint guesses at the display; this measures it. Side by side is the
     point -- the layers are independent, and seeing one fire while the other
     stays clear is the argument. */
  .lanes {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(440px, 1fr));
    gap: 1px; background: var(--rule);
  }
  .lane { background: var(--ground); padding: 20px 28px 22px; }
  /* Phrases wrap as whole phrases, never mid-label. A lane header reading
     "RF / spectrum" over two lines is the sort of thing that only shows up at
     the width you did not test. */
  .lane-head {
    display: flex; align-items: baseline; gap: 12px;
    flex-wrap: wrap; margin-bottom: 16px;
  }
  .lane-title { font-size: 17px; font-weight: 600; white-space: nowrap; }
  .lane-sub { font-size: 13px; color: var(--ink-dim); white-space: nowrap; }
  .lane-condition {
    margin-left: auto; font-size: 13px; font-weight: 500; white-space: nowrap;
  }
  .lane-condition.quiet   { color: var(--quiet); }
  .lane-condition.alarm   { color: var(--alarm); }
  .lane-condition.offline { color: var(--ink-dim); }

  /* --- spectrum ----------------------------------------------------- */
  .spectrum { width: 100%; height: 156px; display: block; }
  .axis-line     { stroke: var(--rule); stroke-width: 1; }
  .spike-known   { stroke: var(--known); stroke-width: 4; }
  .spike-unknown { stroke: var(--alarm); stroke-width: 4; }
  .cap-known     { fill: var(--known); }
  .cap-unknown   { fill: var(--alarm); }
  .axis {
    display: flex; justify-content: space-between;
    font-size: 12px; color: var(--ink-dim); margin-top: 2px;
  }
  .axis-span { color: var(--rule); }

  /* A monitor that has stopped reporting must not look like one that is
     reporting good news. Its last frame stays visible for context, but
     visibly as history. */
  .lane-body.stale { opacity: 0.32; filter: saturate(0.3); }

  /* --- readouts ----------------------------------------------------- */
  .readout { margin-top: 16px; }
  .carrier {
    display: flex; align-items: baseline; gap: 16px;
    padding: 7px 0; border-bottom: 1px solid var(--rule);
  }
  .carrier:last-child { border-bottom: none; }
  .freq { font-size: 22px; font-weight: 500; }
  .freq.unknown { color: var(--alarm); }
  .ppm  { font-size: 15px; color: var(--ink-dim); }
  .tag  { margin-left: auto; font-size: 12px; color: var(--ink-dim); }
  .tag.unknown { color: var(--alarm); font-weight: 600; }

  .sessions { width: 100%; border-collapse: collapse; font-size: 14px; }
  .sessions td { padding: 7px 0; border-bottom: 1px solid var(--rule); }
  .sessions td.net { color: var(--ink-dim); }
  .sessions td.bytes { text-align: right; color: var(--ink-dim); }
  .sessions tr.flagged td { color: var(--alarm); }

  .summary { margin-top: 14px; font-size: 14px; color: var(--ink-dim); }
  .empty { color: var(--ink-dim); font-size: 14px; padding: 28px 0; }

  /* --- alerts ------------------------------------------------------- */
  .alerts { border-top: 1px solid var(--rule); padding: 16px 28px 24px; flex: 1; }
  .alerts h2 { font-size: 14px; font-weight: 600; color: var(--ink-dim); margin: 0 0 12px; }
  .alert-row {
    display: flex; align-items: baseline; gap: 18px;
    padding: 10px 0; border-bottom: 1px solid var(--rule); font-size: 15px;
  }
  .alert-time { color: var(--ink-dim); font-size: 13px; width: 72px; flex: none; }
  .alert-sev  { width: 74px; flex: none; font-weight: 600; font-size: 13px; }
  .alert-sev.critical, .alert-sev.high { color: var(--alarm); }
  .alert-sev.medium { color: var(--attention); }
  .alert-sev.low, .alert-sev.info { color: var(--ink-dim); }
  .alert-what { font-weight: 500; width: 200px; flex: none; }
  .alert-detail { color: var(--ink-dim); font-size: 14px; }

  @keyframes arrive { from { opacity: 0; transform: translateY(-6px); } }
  .alert-row.new { animation: arrive 280ms ease-out; }
  @media (prefers-reduced-motion: reduce) { .alert-row.new { animation: none; } }
</style>
</head>
<body>
  <header>
    <span class="wordmark">GridHawk</span>
    <span class="headline quiet" id="headline">Starting</span>
    <div class="census" id="census"></div>
  </header>
  <div class="lanes" id="lanes"></div>
  <div class="alerts">
    <h2 id="alerts-heading">Alerts</h2>
    <div id="alert-list"></div>
  </div>

<script>
const POLL_MS = __POLL_MS__;
let seenAlerts = new Set();

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function conditionWord(condition) {
  return { quiet: "Clear", alarm: "Unaccounted emitter",
           offline: "Not reporting", attention: "Degraded" }[condition] || condition;
}

/* Draw carriers on a frequency axis.

   The axis is zoomed to the carriers rather than spanning the whole monitored
   band. Two transmitters separated by crystal tolerance sit ~1 kHz apart in a
   150 kHz sweep -- under 1% of the width -- so a full-span axis renders them
   as a single mark and hides the one thing worth seeing. */
function spectrumWindow(carriers, low, high) {
  if (!carriers.length) return [low, high];

  const freqs = carriers.map(c => c.freq_hz);
  const lo = Math.min(...freqs), hi = Math.max(...freqs);
  const centre = (lo + hi) / 2;
  const spread = hi - lo;

  // Show at least 6 kHz, and at least four times the separation, so a pair is
  // clearly two marks with room around them.
  const width = Math.max(6000, spread * 4);
  return [centre - width / 2, centre + width / 2];
}

function spectrum(detail) {
  const carriers = detail.carriers || [];
  const [low, high] = spectrumWindow(
    carriers, detail.low_hz || 0, detail.high_hz || 1);
  const width = 1000, height = 150, base = height - 12, top = 14;

  let svg = `<svg class="spectrum" viewBox="0 0 ${width} ${height}"
                  preserveAspectRatio="xMidYMid meet" role="img"
                  aria-label="${carriers.length} carriers detected">`;
  svg += `<line class="axis-line" x1="0" y1="${base}" x2="${width}" y2="${base}"/>`;

  for (const c of carriers) {
    const x = ((c.freq_hz - low) / (high - low)) * width;
    if (x < 0 || x > width) continue;
    const over = Math.max(0, Math.min(1, (c.over_floor_db || 0) / 45));
    const y = base - Math.max(10, over * (base - top));
    const cls = c.known ? "spike-known" : "spike-unknown";
    svg += `<line class="${cls}" x1="${x.toFixed(1)}" y1="${base}"
                  x2="${x.toFixed(1)}" y2="${y.toFixed(1)}"/>`;
    svg += `<circle class="${c.known ? "cap-known" : "cap-unknown"}"
                    cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="5"/>`;
  }
  svg += `</svg>`;

  /* Axis labels live in HTML, not SVG. Stretching the SVG to fill the panel
     would stretch its text with it, which reads as a strange typeface. */
  const mhz = hz => (hz / 1e6).toFixed(4);
  const span = ((high - low) / 1000).toFixed(1);
  svg += `<div class="axis">
            <span>${mhz(low)} MHz</span>
            <span class="axis-span">${span} kHz shown</span>
            <span>${mhz(high)} MHz</span>
          </div>`;
  return svg;
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
    const unknown = c.known ? "" : " unknown";
    html += `<div class="carrier">
      <span class="freq${unknown}">${(c.freq_hz / 1e6).toFixed(6)}</span>
      <span class="ppm">${c.ppm >= 0 ? "+" : ""}${Number(c.ppm).toFixed(2)} ppm</span>
      <span class="tag${unknown}">${c.known ? "baselined" : "unaccounted"}</span>
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
  if (!sessions.length) {
    return `<div class="empty">No outbound sessions in this window.</div>`;
  }

  let html = `<table class="sessions">`;
  for (const s of sessions.slice(0, 8)) {
    html += `<tr class="${s.allowed ? "" : "flagged"}">
      <td>${esc(s.dst)}</td>
      <td class="net">${esc(s.asn_name)} ${esc(s.cc)}</td>
      <td class="bytes">${Number(s.bytes).toLocaleString()} B</td>
    </tr>`;
  }
  html += `</table>`;

  const flagged = sessions.filter(s => !s.allowed).length;
  const note = flagged
    ? `${flagged} to an unrecognised network`
    : `all ${sessions.length} to authorised networks`;
  html += `<div class="summary">${esc(d.windows || 0)} windows, ${esc(note)}</div>`;
  return html;
}

function render(state) {
  const headline = document.getElementById("headline");
  headline.textContent = state.headline;
  headline.className = "headline " + state.condition;

  const reporting = state.lanes.filter(l => l.condition !== "offline").length;
  document.getElementById("census").innerHTML =
    `${reporting} of ${state.lanes.length} layers reporting<br>${state.alert_count} alerts`;

  document.getElementById("lanes").innerHTML = state.lanes.map(lane => `
    <section class="lane">
      <div class="lane-head">
        <span class="lane-title">${esc(lane.title)}</span>
        <span class="lane-sub">${esc(lane.subtitle)}</span>
        <span class="lane-condition ${lane.condition}">${conditionWord(lane.condition)}</span>
      </div>
      <div class="lane-body${lane.condition === "offline" ? " stale" : ""}">
        ${lane.source === "rf" ? rfLane(lane) : networkLane(lane)}
      </div>
    </section>`).join("");

  const list = document.getElementById("alert-list");
  if (!state.alerts.length) {
    list.innerHTML = `<div class="empty">Nothing raised yet. Both layers are being watched.</div>`;
  } else {
    list.innerHTML = state.alerts.map(a => {
      const key = a.id;
      const isNew = !seenAlerts.has(key);
      seenAlerts.add(key);
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
  } catch (e) { /* keep the last good frame rather than blanking the screen */ }
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
