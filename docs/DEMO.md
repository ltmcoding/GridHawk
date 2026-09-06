# Live demonstration runbook

Two things are shown, both live, both raising real alerts:

1. **Two radios commanded to the identical frequency are told apart** by the
   manufacturing error in their crystals alone.
2. **The inverter's HTTPS traffic is attested** from sniffed packets, and a call
   to an unauthorised endpoint is caught without decrypting anything.

Every detection posts to a web endpoint that updates on a projector.

---

## Machines and roles

| Machine | Runs | Why |
|---|---|---|
| **Feather A** | carrier firmware | the authorised radio |
| **Feather B** | same firmware, same frequency | the undocumented radio |
| **Raspberry Pi** | SDR receiver, packet capture, both monitors | the site monitor |
| **Computer A** | vendor cloud (HTTPS, port 8443) | where the inverter is supposed to talk |
| **Computer B** | alert dashboard (8080) + rogue endpoint (8443) | operations, plus somewhere it should not talk |

**Why the rogue endpoint lives on Computer B:** the allowlist resolves by IP
address, so the authorised and unauthorised endpoints must be on *different
machines*. Two ports on one machine share an address and would be
indistinguishable. Computer B therefore plays two roles — your dashboard, and an
unknown endpoint out on the internet.

**One honest note:** the Pi both generates the inverter traffic and captures it,
so the demo fits in three boxes. In a real deployment the monitor is a passive
tap and the inverter is a separate device. The capture is still genuinely real
packets crossing a real interface.

---

## One-time setup

### 1. Flash both Feathers

Arduino IDE → **Preferences → Additional Board Manager URLs**, add:

```
https://adafruit.github.io/arduino-board-index/package_adafruit_index.json
```

Then **Tools → Board → Boards Manager**, install **Adafruit SAMD Boards**.
Select **Adafruit Feather M0**, open `firmware/feather_cw/feather_cw.ino`, and
upload to **both** boards without changing anything.

> Flash both with the **same** nominal frequency. Do not "correct" one of them.
> The difference between them is the entire experiment.

Solder a **16.5 cm** wire to each board's antenna pad — a quarter wavelength at
433 MHz. Without an antenna the radio barely radiates and the demo fails
mysteriously.

Check each board over serial at **115200 baud**. You should see
`RFM69 version register: 0x24`. Anything else means the radio is not responding.

### 2. Prepare the Pi

```bash
sudo apt update
sudo apt install rtl-sdr tcpdump git python3

git clone git@github.com:ltmcoding/GridHawk.git
cd GridHawk

# Confirm the SDR is seen
rtl_test -t          # Ctrl-C after a few seconds
```

If `rtl_test` reports the device is in use, blacklist the TV tuner driver:

```bash
echo 'blacklist dvb_usb_rtl28xxu' | sudo tee /etc/modprobe.d/blacklist-rtl.conf
sudo reboot
```

### 3. Fill in addresses

Find each machine's address (`ip addr` on Linux, `ipconfig getifaddr en0` on
macOS, `ipconfig` on Windows), then on the Pi:

```bash
cp demo/asn_map.example.json demo/asn_map.json
nano demo/asn_map.json
```

```json
{
  "192.168.1.50": [64500, "VENDOR-CLOUD-PRIMARY", "DE"],
  "192.168.1.60": [64666, "UNKNOWN-TRANSIT", "CN"]
}
```

Computer A's address is the authorised one. Computer B's is the rogue.
Anything not listed resolves to UNKNOWN, which counts as unauthorised — so a
typo produces an alert rather than silence.

### 4. Fill in the inventory (Layer 1 join)

This is what makes an alert say *"Sungrow SG110CX, 501 kW, Kern County"* instead
of an anonymous address. Alert priority is `severity x MW behind the device`,
so a utility-scale unit outranks a rooftop raising the identical flag.

```bash
cp demo/inventory.example.json demo/inventory.json
nano demo/inventory.json
```

Key it by the Pi's own address (for network findings) and by the band name
(for RF findings). The per-install capacities in the example are the real
figures from the Grid Lockout analysis of California Rule 21 records.

A device missing from the inventory still alerts -- it is simply ranked last.
An unknown device on the network is itself worth noticing.

### 5. Check the whole path before the day

```bash
# Computer B
python3 -m sinks.alert_receiver --port 8080

# Pi -- should appear on the dashboard within a second
python3 -c "
from sinks.webhook import AlertSink
from core.events import Finding
AlertSink('http://192.168.1.60:8080/alert').send(
    Finding(ts=0, source='rf', subject='test', kind='excess_emitter',
            severity='info', detail={'note': 'connectivity check'}))"
```

---

## If the hardware fails: fallback mode

**Rehearse this once before the day.** Recorded data drives the identical
detection and alerting code, so the dashboard still fills with real alerts if
the SDR will not enumerate or a Feather will not flash.

```bash
make fallback          # regenerate the recordings (already committed)

# Act 1 without a radio
python3 demo/rf_monitor.py baseline --replay demo/fallback/rf_baseline.csv
python3 demo/rf_monitor.py monitor  --replay demo/fallback/rf_authorised.csv \
    --alert-url http://192.168.1.60:8080/alert      # stays silent
python3 demo/rf_monitor.py monitor  --replay demo/fallback/rf_two_radios.csv \
    --alert-url http://192.168.1.60:8080/alert      # names the rogue
python3 demo/rf_monitor.py monitor  --replay demo/fallback/rf_rogue_only.csv \
    --alert-url http://192.168.1.60:8080/alert      # counting would miss this

# Act 2 without a network (no sudo, no tcpdump)
python3 demo/tls_monitor.py --replay demo/fallback/tls_normal.pcap \
    --asn-map demo/asn_map.json --port 8443 --window 5 \
    --alert-url http://192.168.1.60:8080/alert      # stays silent
python3 demo/tls_monitor.py --replay demo/fallback/tls_rogue.pcap \
    --asn-map demo/asn_map.json --port 8443 --window 5 \
    --alert-url http://192.168.1.60:8080/alert      # flags the call
```

**Say that you are in fallback mode if you use it.** The recordings are
synthetic and clearly labelled as such. Claiming a live measurement you did not
take would undo the credibility the rest of the project is built on.

---

## Running the demo

### The short version: one command

Everything below can be driven by a single script that pauses between steps and
waits for you to switch radios:

```bash
python3 demo/run_demo.py --mac Landons-MacBook-Pro-4.local
```

It checks the dashboard, the vendor cloud and the rogue endpoint are all
reachable before starting, walks the six steps in order, tells you exactly which
radio to switch and when, and reports what it expected against what it got at
each step. A step that goes wrong is obvious at the time rather than something
you notice later.

**Use the `.local` name, not an IP.** DHCP moves addresses, and a pinned address
fails silently -- alerts simply stop arriving with nothing on screen to say so.

**Rehearse it first with no hardware at all:**

```bash
make demo-rehearse
```

Same script, same six steps, recorded data. Worth doing once so the ordering is
familiar before anyone is watching.

The rest of this document is what the script runs, if you would rather drive it
by hand or need to debug a step.

## Start these and leave them running

**Computer A** — the vendor cloud:
```bash
python3 -m sim.cloud.server --bind 0.0.0.0 --port 8443
```

**Computer B** — dashboard, then the rogue endpoint in a second terminal:
```bash
python3 -m sinks.alert_receiver --bind 0.0.0.0 --port 8080
python3 -m sim.cloud.server --bind 0.0.0.0 --port 8443
```

Open `http://<computer-b>:8080/` on the projector. It refreshes itself.

---

### Act 1 — Two radios, one frequency

**Power on Feather A only. Leave Feather B off.** Over serial, press `t`.

On the Pi:

```bash
python3 demo/rf_monitor.py baseline \
  --baseline-file demo/baseline.json \
  --nominal 433920000 --span 150000 --bin-hz 250 --sweeps 12
```

This records where Feather A *actually* transmits. Expect a few ppm off
nominal. Read the number out loud — it is the crystal error, made visible.

> If it baselines **two** emitters, Feather B was transmitting. Power it off and
> run again, or B becomes permanently "authorised."

Now start monitoring:

```bash
python3 demo/rf_monitor.py monitor \
  --baseline-file demo/baseline.json \
  --alert-url http://192.168.1.60:8080/alert \
  --nominal 433920000 --span 150000 --bin-hz 250
```

One carrier per sweep, no alerts. **This is the false-positive check** — the
authorised radio, running continuously, stays silent. Let it run a few sweeps so
the audience sees it holding quiet.

**Now power on Feather B and press `t`.**

Identical firmware, identical commanded frequency. Within a sweep or two the Pi
reports **two** carriers, several kHz apart, and posts a `critical`
`excess_emitter` alert naming the one it does not recognise.

**The closing move:** switch Feather A **off**, leaving only B. The carrier count
is back to one — but it is the *wrong* one, and the alert fires again. A detector
that merely counted radios would see one radio and say nothing.

### Act 2 — HTTPS attestation

On the Pi, start the monitor (needs root to open the interface):

```bash
sudo python3 demo/tls_monitor.py \
  --interface wlan0 --port 8443 \
  --asn-map demo/asn_map.json \
  --alert-url http://192.168.1.60:8080/alert \
  --window 10
```

In a second terminal, start normal inverter traffic:

```bash
python3 demo/inverter_traffic.py --host 192.168.1.50 --port 8443
```

Each window lists the sessions it saw — destination, network, country, bytes —
and reports **no findings**. Say plainly that the contents are encrypted and
never decrypted: only the envelopes are read.

**Now the rogue call.** Third terminal:

```bash
python3 demo/rogue_call.py --host 192.168.1.60 --port 8443
```

Within one window the monitor flags `new_asn` at `high` severity and posts it.
The dashboard shows the destination, the unrecognised network, and the country.

### Act 3 — The dashboard

By now it holds RF and network alerts side by side: two independent layers, two
different failure modes, one alert stream. That is the point of the layered
design — the radio layer catches what the network layer structurally cannot see.

---

## If something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| `rtl_power not found` | tools missing | `sudo apt install rtl-sdr` |
| `No supported devices found` | dongle not seen, or TV driver holding it | replug; blacklist `dvb_usb_rtl28xxu` |
| Baseline finds no carrier | radio not transmitting, no antenna, or wrong band | press `t`; check `?` output; solder the antenna |
| Many spurious carriers | receiver overloaded | move the boards further away; lower power with `p 0` |
| Two carriers baselined | B was on during baseline | power B off, baseline again |
| Both radios look identical | one board's frequency was "corrected" | reflash both with the same value |
| `tcpdump: Operation not permitted` | needs root | run with `sudo` |
| Every session alerts | address not in `asn_map.json` | add the real IP |
| No alerts reach the dashboard | firewall, or bound to localhost | bind `0.0.0.0`; check with `curl` |
| No traffic captured | wrong interface | `ip addr` — usually `wlan0` or `eth0` |
| Schedule rejected as scenario time | windows written as seconds-from-zero | live capture needs absolute times; use `maintenance_windows_iso` |
| Alerts show no device or capacity | inventory missing or wrong key | check `demo/inventory.json` is keyed by the Pi's address and band name |
| Any hardware failure at all | — | switch to fallback mode above and say so |

**Power the Feathers from battery packs, not from the Pi.** Sharing a supply
with the receiver couples transmitter energy down the USB cable, and you end up
measuring your own wiring.

---

## What this proves, and what it does not

**Proves:** two radios commanded to the same frequency are separable by their
crystal error alone; a baselined emitter can be told from an unbaselined one,
including when the authorised one is silent; encrypted traffic can be attested
from metadata without decryption; and every detection reaches an operator.

**Does not prove:** that real inverters behave this way. There is no bench
inverter in this demo. The device profile is assumed, the endpoints are stand-ins,
and the radios are development boards rather than an inverter's own transmitter.

Say so. The measurement is real; the subject is a stand-in. That distinction is
what makes the rest of the claim credible.
