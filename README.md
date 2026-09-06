# Inverter Security Scanner Project

## Introduction

This project is trying to ``scan'' radio signals emitted from power inverters to determine of any unauthorized signals (i.e. not from standard fucntions like firmware updates) are emitted. To do so, we will assume othw following input:

### Input

We are given raw input data from a directional antenna directed at the inverter. We should construct the software in such a way that extending one function would enable it to run on both a laptop and a smaller computer like a Raspberry Pi Zero.

## Assumed Knowns

For us to accurately flag insecure inverters, we need to assume the following are known to us:

- We have an idea of tha frequency range (or a specific frequency) that authorized signals come from, ANY other frequency ranges within a certain decibel level of our main frequency should be flagged.
    - We should take our RF data either through a test stream or a SDR, using rtl_power to parse the data and detect unauthorized frequencies.
- We know the IP addresses of authorized signals, ANY other IP address is considered unauthorized. These IP address permissions should change depending on the request type.
- We know the type of data given by our firmware update, ANY other data should be flagged.
- Generally, packet matching is more complicated, but include some simple pattern-matching logic (though regex preferrably) in the event we can use this to distinguish authorization.

[^note] We have NO bench inverter. With no device there is no firmware extraction, therefore no client certificate, therefore no mTLS interception and no TLS payload visibility. Layer 2 is metadata-only; see `docs/STATUS.md`.

## Rough Sketch of Computer Logic

We'll divide our program into two threads. Our first thread scans the raw RF data to detect different critical frequencies, and if an unauthorized signal goes out, flag it. This thread should run if we feed test data into our device, or we introduce an SDR device that starts sniffing the frequencies. Otherwise, the thread should sleep.

Our second thread will find and scan incoming and outgoing HTTPS requests. If any part of these requests don't match our authorized signals in a similar manner to the rules above, flag it. In scanning the HTTPS requests, we should also send metrics to our central we server using the following [open-source library](https://github.com/szlaskidaniel/solar-inverter-modbus-registers)

When we flag an inverter, we should notify a central web server, which takes the inverter ID, which it then will use to notify the end user. Assumes this server endpoint exists, and make a placeholder name for it, outling the format the HTTPS request takes.

## BOM

[Raspberry Pi](https://www.microcenter.com/product/704295/raspberry-pi-5-1gb)
[RTL-SDR](https://www.microcenter.com/product/711017/rtl2832u-r828d-tcxo-bios-t-hf-software-defined-radio-with-dipole-antenna-kit)
SD card

## Implementation

This repo implements **Layers 2 and 3** — network egress attestation and RF
egress detection. Layer 1 (fleet inventory) lives in the Grid Lockout artifact.

```
make scenarios && make detect && make score    # TLS egress, 12 seeds
make rf                                        # RF carrier detection
make test                                      # 70 tests (RF, pcap, demo)
```

No dependencies — Python 3.11+ standard library only.

### Documentation

Full docs in [`docs/`](docs/README.md):

| | |
|---|---|
| [ARCHITECTURE](docs/ARCHITECTURE.md) | System design, data flow, module map |
| [COLLECTORS](docs/COLLECTORS.md) | Each collector, including the two not yet built |
| [RULES](docs/RULES.md) | Every detection rule and its blind spots |
| [RF](docs/RF.md) | Physics, algorithm, resolution limits, bench protocol |
| [SIMULATION](docs/SIMULATION.md) | Test harness and red/blue methodology |
| [RESULTS](docs/RESULTS.md) | Measured numbers and threats to validity |
| [ENGINEERING LOG](docs/ENGINEERING-LOG.md) | Bugs found, decisions, failed hypotheses |
| [API](docs/API.md) | Function-level reference |

### Status

TLS egress: precision **1.00**, recall **1.00**, zero false positives when the
site's firmware schedule is supplied (0.90 / 1.00 without it). RF: resolves
emitters separated by more than ~1.3x the carrier's occupied bandwidth, and
identifies unaccounted carriers against a baseline.

**RF is validated on real hardware.** Two radios commanded to the same
frequency measured 1,199 Hz (2.77 ppm) apart from crystal tolerance alone; zero
false positives across 10 sweeps of live air; correct detection across 112
continuous sweeps, including the case where the authorised radio is silent and
only the rogue transmits.

**The network layer is still synthetic.** There is no bench inverter, and
device profile constants are assumed. See
[threats to validity](docs/RESULTS.md#threats-to-validity).
