# Engineering log

Bugs the harness found, decisions taken, and things that were tried and failed.
Recorded because the failures are more instructive than the final numbers, and
because a reviewer should be able to see what was tuned and what was fixed.

---

## Bug 1 — threshold-crossing merged overlapping carriers

**Symptom.** Two emitters 8.9 kHz apart reported as one carrier, 17 kHz wide,
centred at 433.913190 MHz — a frequency at which nothing was transmitting.

**Cause.** Carriers were located as contiguous runs of bins above a threshold.
Each 3 kHz-wide carrier at −25 dB stays above a −50 dB threshold out to
±4.3 kHz, so at 8.9 kHz separation the two above-threshold regions touch and
form a single run. The reported centre was the power-weighted mean of two real
signals.

**Fix.** Prominence-based peak detection: local maxima each required to clear
3 dB above the highest saddle joining them to a taller peak. The dip between
two carriers is real even when both flanks stay above the noise floor.

**Caught by:** the `dual` preset in the very first RF test run.

---

## Bug 2 — cadence rule double-reported already-explained sessions

**Symptom.** Precision 0.64 with 10 false positives, all `off_cycle_burst`.
Seeds with three injected anomalies produced three spurious cadence findings.

**Cause.** Every injected session — regardless of its intended anomaly type —
inserts an extra event into the stream and therefore perturbs cadence. A
`new_asn` injection was correctly caught by the ASN rule *and* incorrectly
re-reported by the cadence rule as a second, independent anomaly.

**Fix.** One session, one finding. Findings whose interval endpoints are
already claimed by a stronger rule are suppressed.

**Note on method:** this is deduplication, not threshold tuning. No constant
was changed. Precision 0.64 → 0.90, recall unchanged at 1.00.

---

## Bug 3 — non-contiguous band edges (found, not the culprit)

**Symptom.** Band edges printed as `[(2.301, 2.845), (3.088, 5.404), …]` — a
hole between 2.845 and 3.088.

**Cause.** `_log_bands` started each band at `ls[prev]` rather than at the
previous band's upper edge, leaving gaps. `_band_of` falls through to the last
band, so every session in a hole was assigned to an unrelated band.

**Fix.** Each band now starts where the previous ended.

**Honest note:** fixing this changed the measured numbers *not at all*. It was a
real defect found while chasing a different problem, and it was not the cause of
that problem. Recorded because "I fixed something and the numbers were
identical" is exactly the signal that says keep looking.

---

## Bug 4 — banding collapse produced 274 false positives

**Symptom.** At a 24-hour window, one seed (8080) produced 263 spurious
`off_cycle_burst` findings; the 12-seed aggregate was 274 FPs and precision
0.08. At 72 hours it reached 3 338 FPs and precision 0.01.

**Cause.** Channel separation by byte magnitude collapsed. Band 0 spanned
200–12 497 bytes — heartbeat *and* telemetry pooled into one band. Its median
gap (56.9 s) reflected the dominant heartbeat channel, so 266 perfectly normal
telemetry sessions appeared to arrive "early." The collapse happens when a
sparse channel bridges two dense clusters and the log-gap used for splitting
falls below the threshold.

**Two failed fixes, recorded because they were wrong:**

1. *Hypothesis: the observation window is too short to learn rare channels.*
   Tested by sweeping window length. **Refuted** — longer windows were
   dramatically worse (2.00 → 92.72 FP/device-day), the opposite of the
   prediction.
2. *Hypothesis: mixed bands show high gap dispersion, so guard on MAD/median.*
   Implemented; the numbers came back **byte-identical**. Measurement showed
   the collapsed band's dispersion was 0.102 — well below the 0.25 threshold.
   A dominant channel keeps the MAD small while a second channel injects
   hundreds of short gaps: the distribution is **bimodal, not wide**.

**Actual fix.** Guard on firing *rate*, not spread. A rule flagging a large
fraction of all sessions is mismodelling the channel rather than detecting
anomalies:

```python
if len(short) > max(3, 0.05 * len(gaps)):
    continue   # abstain for this band
```

274 → 11 FPs at 24 h; 3 338 → 23 at 72 h.

**Cost, stated plainly.** Genuine off-cycle bursts inside an unseparable band
are now missed, and the abstention is silent. A production build should log
every abstention — a detector that quietly stops detecting is worse than one
that fails loudly.

**Method note.** Two wrong hypotheses in a row, both producing identical
numbers, is what forced measuring the actual distribution instead of reasoning
about it. The lesson generalises: when a fix changes nothing, the model is
wrong, not the threshold.

---

## Bug 5 — test entrypoint ordering

`test_identification()` was appended after the `if __name__ == "__main__"`
block, so it was undefined when `main()` ran. Entry point moved to the end of
the file. Trivial, listed for completeness.

---

## Decision 1 — metadata-only TLS

No bench inverter → no firmware extraction → no client certificate → no mTLS
interception → no payload visibility.

This matches Grid Lockout's own coverage matrix, which already lists "TLS
payload contents" in Layer 2's cannot-see column. The `tls_local` collector
(inverter-as-server) was scoped and then **cut** for the same reason: there is
no device to inspect.

The README's claim to possess a bench inverter was corrected in the same commit
that added the code. It contradicted Grid Lockout's limitations section, which
is the artifact's principal credibility asset.

---

## Decision 2 — pure standard library

No scapy, no numpy, no pymodbus. `collectors/pcap.py` is a from-scratch classic
pcap reader (~120 lines) written specifically to avoid a scapy dependency.

**Rationale:** a hackathon demo that requires `pip install` on conference Wi-Fi
is a demo that fails. `requirements.txt` documents the absence deliberately.

**Cost:** the pcap reader handles classic pcap only, not pcapng. It raises a
clear error rather than misparsing.

---

## Decision 3 — partial maintenance-window suppression

A scheduled firmware update explains **timing** and **volume**. It never
explains a **new destination**.

Suppressing all rules inside a maintenance window would publish a predictable
blind spot an adversary can simply wait for. So `volume_spike` and
`off_cycle_burst` are suppressed inside windows; `new_asn`, `geo_drift` and
`tunnel_indicator` stay armed.

Measured: supplying the schedule eliminated **every** false positive at both
2 h (2 → 0) and 24 h (11 → 0), recall unchanged at 1.00.

This is the single highest-value input in the system, and it costs nothing —
it is operator change-log knowledge, not a detection improvement.

---

## Decision 4 — identification over counting

Baselining the authorised emitter converts "is this band too crowded?" into
"which carrier is unaccounted for?"

Strictly stronger. The decisive case: authorised radio **silent**, rogue
transmitting. Counting sees one carrier where one was expected and says
nothing. Identification knows that carrier is not the baselined one.

Also survives thermal drift of the authorised emitter (2 kHz default tolerance)
and simultaneous transmission.

---

## Decision 5 — interval-localised findings

A cadence anomaly cannot be localised to an instant: an injected session splits
one interval into two, and either endpoint could be the intruder. Rather than
guess, findings carry `detail.window_start` and the scorer credits a match
anywhere in the interval.

Alternative considered and rejected: widen the global scoring tolerance. That
would have loosened matching for *all* rules to accommodate one, inflating
apparent precision everywhere.

---

## Things not built

| Item | Why not | Priority |
|---|---|---|
| `correlate/` (Layer 1 join) | Time | **Highest** — the only collector backed by real data (2.1 M resolved records); `mw_at_risk` is inert without it |
| `modbus` collector | Time | High — needs no hardware; `pymodbus` emulator plus SunSpec Model 7xx |
| Layer 5 attestation register | Time | High — concrete standards artifact, no hardware needed |
| Real ASN resolution | Fixture sufficed | Medium — `asn_lookup` is already the seam |
| mbedTLS client | Would enable JA3 claims | Low — currently no JA3 detection is claimed |
| Abstention logging | Found late | Medium — silent recall loss is a real hazard |
