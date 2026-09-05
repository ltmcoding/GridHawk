"""The endpoint alerts are posted to, plus a dashboard for watching them.

Run this on the operations machine. It accepts POSTed findings and serves a
page that refreshes on its own, so it can be left on a projector.

Deliberately self-contained: the demo must not depend on an internet service
being reachable from the venue. Point the monitors at a real endpoint later by
changing one URL.
"""

from __future__ import annotations

import argparse
import html
import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


PAGE_REFRESH_SECONDS = 2
MAX_ALERTS_RETAINED = 200

SEVERITY_COLOURS = {
    "critical": "#b3001b",
    "high": "#d94f04",
    "medium": "#b08900",
    "low": "#4a6fa5",
    "info": "#5a6570",
}

received_alerts: list[dict] = []


def _format_detail(detail: dict) -> str:
    """Flatten a finding's detail into one readable line.

    Nested values are skipped: the table needs a single line per alert, and a
    projector at the back of a room cannot read a wrapped JSON blob.
    """
    parts = []
    for key, value in sorted(detail.items()):
        if isinstance(value, (dict, list)):
            continue
        parts.append(f"{html.escape(str(key))}={html.escape(str(value))}")
    return "  ".join(parts)


def _render_row(alert: dict) -> str:
    """One table row for one alert."""
    severity = alert.get("severity", "info")
    colour = SEVERITY_COLOURS.get(severity, SEVERITY_COLOURS["info"])

    return f"""
        <tr>
          <td class="time">{html.escape(alert.get('received_at', ''))}</td>
          <td><span class="sev" style="background:{colour}">{html.escape(severity)}</span></td>
          <td class="kind">{html.escape(str(alert.get('kind', '')))}</td>
          <td class="src">{html.escape(str(alert.get('source', '')))}</td>
          <td class="subj">{html.escape(str(alert.get('subject', '')))}</td>
          <td class="detail">{_format_detail(alert.get('detail', {}))}</td>
        </tr>"""


def _render_page() -> bytes:
    """The whole dashboard. Newest alerts first, since those are the news."""
    rows = []
    for alert in reversed(received_alerts):
        rows.append(_render_row(alert))

    if not rows:
        rows.append("""
        <tr><td colspan="6" class="empty">
          No alerts yet. Monitoring is running; this page updates itself.
        </td></tr>""")

    return f"""<!doctype html>
<html><head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="{PAGE_REFRESH_SECONDS}">
<title>GridHawk alerts</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 0; background: #12151a; color: #e8eaed; }}
  header {{ padding: 18px 26px; border-bottom: 1px solid #2a2f38; }}
  h1 {{ margin: 0; font-size: 20px; letter-spacing: 0.3px; }}
  .sub {{ color: #98a0ab; font-size: 13px; margin-top: 4px; }}
  .count {{ float: right; font-size: 32px; font-weight: 600; line-height: 1; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 10px 12px; color: #98a0ab;
        font-weight: 500; border-bottom: 1px solid #2a2f38; }}
  td {{ padding: 9px 12px; border-bottom: 1px solid #1e232b; vertical-align: top; }}
  .sev {{ padding: 2px 8px; border-radius: 3px; font-size: 11px;
          text-transform: uppercase; letter-spacing: 0.5px; color: #fff; }}
  .time {{ color: #7d8894; white-space: nowrap; font-variant-numeric: tabular-nums; }}
  .kind {{ font-weight: 600; }}
  .src, .subj {{ color: #b6bec8; }}
  .detail {{ color: #8d97a3; font-family: ui-monospace, Menlo, monospace; font-size: 12px; }}
  .empty {{ text-align: center; color: #6d7681; padding: 40px; }}
</style></head>
<body>
<header>
  <span class="count">{len(received_alerts)}</span>
  <h1>GridHawk &mdash; unauthorised emitter and egress alerts</h1>
  <div class="sub">Layer 2 network egress attestation &middot; Layer 3 RF egress detection</div>
</header>
<table>
  <tr><th>received</th><th>severity</th><th>kind</th>
      <th>source</th><th>subject</th><th>detail</th></tr>
  {''.join(rows)}
</table>
</body></html>""".encode("utf-8")


class AlertHandler(BaseHTTPRequestHandler):
    """Accepts POSTed findings and serves the dashboard."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format_string, *args):
        """Silence the default request log, so the console shows only alerts."""

    def _respond(self, status: int, body: bytes, content_type: str) -> None:
        """Send one complete response."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        """Receive a finding from a monitor.

        Stamps its own arrival time rather than trusting the sender's clock,
        which is not synchronised with this machine's.
        """
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)

        try:
            alert = json.loads(raw)
        except json.JSONDecodeError:
            self._respond(400, b'{"error":"invalid json"}', "application/json")
            return

        alert["received_at"] = datetime.now(timezone.utc).strftime("%H:%M:%S")
        received_alerts.append(alert)
        while len(received_alerts) > MAX_ALERTS_RETAINED:
            received_alerts.pop(0)

        print(f"[{alert['received_at']}] {alert.get('severity', '?'):<8} "
              f"{alert.get('kind', '?'):<18} from {alert.get('source', '?')}")

        self._respond(200, b'{"ok":true}', "application/json")

    def do_GET(self):
        """Serve the dashboard, or the raw alert list as JSON."""
        if self.path.startswith("/alerts.json"):
            body = json.dumps(received_alerts).encode("utf-8")
            self._respond(200, body, "application/json")
            return
        self._respond(200, _render_page(), "text/html; charset=utf-8")


def main() -> None:
    """Run the receiver until interrupted."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0",
                        help="0.0.0.0 so the Pi on the LAN can reach it")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.bind, args.port), AlertHandler)
    print(f"alert receiver listening on http://{args.bind}:{args.port}")
    print(f"  dashboard : http://<this-machine-ip>:{args.port}/")
    print(f"  post to   : http://<this-machine-ip>:{args.port}/alert")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
