# GridHawk documentation

GridHawk implements **Layers 2 and 3** of the Grid Lockout control stack:
network egress attestation and RF egress detection for grid-tied solar
inverters.

## Start here

| Document | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design, data flow, module map, design trade-offs |
| [COLLECTORS.md](COLLECTORS.md) | Each collector in detail, including the two not yet built |
| [RULES.md](RULES.md) | Every detection rule, its thresholds, and its blind spots |
| [RF.md](RF.md) | RF physics, detection algorithm, resolution limits, bench protocol |
| [SIMULATION.md](SIMULATION.md) | The test harness and the red/blue methodology |
| [RESULTS.md](RESULTS.md) | All measured numbers, with threats to validity |
| [ENGINEERING-LOG.md](ENGINEERING-LOG.md) | Bugs found, decisions taken, hypotheses that failed |
| [API.md](API.md) | Function-level reference |
| [DEMO.md](DEMO.md) | **Live demonstration runbook** — hardware, wiring, and the script to run |
| [STATUS.md](STATUS.md) | One-page summary |

## Quick start

```
make scenarios && make detect && make score    # TLS egress, 12 seeds
make rf                                        # RF carrier detection
make test                                      # 34 tests (RF + pcap)
```

No dependencies. Python 3.11+ standard library only.

## What this does and does not claim

**Does:** the pipeline works end to end; the rules fire on specified traffic
shapes at a measured false-positive rate; the RF detector separates emitters
above a characterised resolution limit and identifies unaccounted carriers
against a baseline.

**Does not:** claim validation against real inverter traffic or real RF. There
is no bench inverter. Device profile constants are assumed. Every RF result is
synthetic.

That distinction is load-bearing — see [RESULTS.md](RESULTS.md#threats-to-validity).
