"""Live spectrum capture: drive rtl_power and hand sweeps to the RF detector.

`rtl_power` sweeps a frequency range and prints one CSV row per chunk of that
range. Rows sharing a timestamp together make up one complete sweep, so this
module buffers rows until the timestamp changes and then releases the sweep.

The detector itself does not change between live and replayed data -- it
receives the same (frequency, power) pairs either way.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

from collectors.rf import RTL_POWER_METADATA_COLUMNS


# rtl_power is told to run forever; we stop it by terminating the process.
RUN_FOREVER = "0"

# Gain in dB. A fixed gain is important: automatic gain control would change
# the noise floor between sweeps and move the detection threshold underneath us.
DEFAULT_GAIN_DB = "30"


def is_available() -> bool:
    """True when the rtl_power binary can be found."""
    return shutil.which("rtl_power") is not None


def build_command(freq_low_hz: float, freq_high_hz: float, bin_hz: float,
                  integration_s: float, gain_db: str = DEFAULT_GAIN_DB,
                  device_index: int = 0) -> list[str]:
    """Assemble the rtl_power invocation."""
    frequency_argument = f"{int(freq_low_hz)}:{int(freq_high_hz)}:{int(bin_hz)}"
    return [
        "rtl_power",
        "-f", frequency_argument,
        "-i", str(integration_s),
        "-g", gain_db,
        "-d", str(device_index),
        "-e", RUN_FOREVER,
        "-",                       # write CSV to stdout
    ]


def _parse_row(line: str):
    """Turn one rtl_power CSV line into (timestamp, [(freq_hz, power_db), ...]).

    Returns None for header lines and anything malformed.
    """
    fields = line.split(",")
    if len(fields) < RTL_POWER_METADATA_COLUMNS + 1:
        return None

    try:
        timestamp = f"{fields[0].strip()} {fields[1].strip()}"
        frequency_low = float(fields[2])
        frequency_step = float(fields[4])

        powers = []
        for cell in fields[RTL_POWER_METADATA_COLUMNS:]:
            text = cell.strip()
            if text != "":
                powers.append(float(text))
    except ValueError:
        return None

    bins = []
    for offset, power in enumerate(powers):
        bins.append((frequency_low + offset * frequency_step, power))
    return timestamp, bins


def stream_sweeps(freq_low_hz: float, freq_high_hz: float, bin_hz: float,
                  integration_s: float = 1.0, gain_db: str = DEFAULT_GAIN_DB,
                  device_index: int = 0, max_sweeps: int | None = None):
    """Yield complete sweeps from a running rtl_power process.

    Each sweep is a list of (frequency_hz, power_db) pairs sorted by frequency,
    matching what `collectors.rf.parse_rtl_power` produces from a file.
    """
    if not is_available():
        raise RuntimeError(
            "rtl_power not found. Install the rtl-sdr tools:\n"
            "  Raspberry Pi / Debian:  sudo apt install rtl-sdr\n"
            "  macOS:                  brew install librtlsdr"
        )

    command = build_command(freq_low_hz, freq_high_hz, bin_hz,
                            integration_s, gain_db, device_index)
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    current_timestamp = None
    current_bins: list[tuple[float, float]] = []
    sweeps_emitted = 0

    try:
        for line in process.stdout:
            parsed = _parse_row(line)
            if parsed is None:
                continue
            timestamp, bins = parsed

            # A new timestamp means the previous sweep is complete.
            if current_timestamp is not None and timestamp != current_timestamp:
                yield sorted(current_bins)
                sweeps_emitted += 1
                current_bins = []
                if max_sweeps is not None and sweeps_emitted >= max_sweeps:
                    return

            current_timestamp = timestamp
            current_bins.extend(bins)

    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

        # Surface a device error rather than looking like an empty capture.
        if process.stderr is not None:
            remaining = process.stderr.read()
            if remaining and "No supported devices found" in remaining:
                print("rtl_power: no SDR detected -- is the dongle plugged in?",
                      file=sys.stderr)
