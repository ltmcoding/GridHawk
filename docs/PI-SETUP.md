# Setting up the Raspberry Pi from scratch

For a Pi 5 straight out of the box, driven from a Mac. Roughly 45 minutes,
most of it waiting for downloads.

---

## First: "connected to my computer" doesn't do what you'd hope

A Pi 5 plugged into your laptop by USB-C gets **power and nothing else**. There
is no data link, no drive appears, and no screen. Unlike some older models, the
Pi 5 cannot pretend to be a USB device.

Worse, a laptop USB-C port supplies nowhere near enough power. The Pi 5 wants
**5 V at 5 A (27 W)**. A laptop port typically gives 5 V at 0.9–3 A. It may
appear to boot and then fail in ways that look like software bugs: random
freezes, corrupted files, a dead SD card. Adding the SDR makes it worse.

**Get a proper USB-C power supply before anything else.** The official
Raspberry Pi 27 W one, or any USB-C PD supply rated 5 V/5 A. This is the single
most common way a new Pi wastes an afternoon.

The Pi will talk to your Mac **over your network**, not over the cable.

---



## What you need in front of you


| Item                          | Notes                                     |
| ----------------------------- | ----------------------------------------- |
| Raspberry Pi 5                | ✅ have                                    |
| microSD card                  | ✅ have (32 GB)                            |
| **USB-C power supply, 27 W**  | ⚠️ **not in your cart** — get this        |
| **A way to read the SD card** | ⚠️ none detected on your Mac              |
| Wi-Fi name and password       | the Pi joins the same network as your Mac |


Your Mac is currently on **192.168.8.196**, so the Pi needs to join that same
network to be reachable.

On the SD reader: your card came with a full-size adapter, so a built-in SD slot
works. If your Mac has no slot, any USB SD reader will do — Micro Center has
them for a few dollars.

**No monitor or keyboard needed.** We will set the Pi up headless: it joins
Wi-Fi on first boot and you connect from your Mac over the network.

---



## Step 1 — Install Raspberry Pi Imager on the Mac

```bash
brew install --cask raspberry-pi-imager
```

This is the tool that writes an operating system onto the card.

## Step 2 — Write the OS to the card

Insert the card (in its adapter) into your Mac, then open **Raspberry Pi
Imager**.

**Choose Device:** Raspberry Pi 5

**Choose OS:** `Raspberry Pi OS (other)` → **Raspberry Pi OS Lite (64-bit)**

> Take *Lite*, not the normal version. You can check afterwards with
> `cat /Volumes/bootfs/issue.txt` — it names the pi-gen stage it was built
> from. `stage2` is Lite; `stage4` or `stage5` is a desktop image, which on a
> 1 GB Pi will be noticeably slower.
> Lite has no desktop, which is right here:
> nothing needs a screen, and it leaves more memory for the work. Your Pi has
> 1 GB, so this matters.

**Choose Storage:** your SD card. **Check this twice** — Imager will erase
whatever you select, and picking the wrong disk erases the wrong thing.

Then click **Next → Edit Settings**. This is the part that makes the headless
setup work, so do not skip it:

**General tab**

- Hostname: `gridhawk`
- Username: **write down exactly what you set here.** Imager may keep a
  previous value rather than the one you expect — ours ended up as `hawk`,
  and connecting as the wrong user fails with a confusing "permission
  denied" that looks like a password problem.
- Configure wireless LAN: your Wi-Fi name and password exactly as they appear
- Wireless LAN country: `US`
- Set locale settings: your timezone

**Services tab**

- ✅ **Enable SSH** → *Use password authentication*

> You can instead paste the contents of `~/.ssh/id_ed25519.pub` for key-based
> login. Password is simpler for a first setup; either works.

Save, then **Yes** to apply, then **Yes** to erase. Writing and verifying takes
about five minutes.

### Verifying the card before you boot

Put the card back in the Mac and check that the settings actually landed:

```bash
grep -E "hostname|name:" /Volumes/bootfs/user-data
grep -A3 access-points /Volumes/bootfs/network-config
```

Recent Imager writes **cloud-init** files — `user-data`, `network-config`, and
`meta-data` — and puts `ds=nocloud` in `cmdline.txt`. Older versions instead
wrote `custom.toml` or `firstrun.sh`. Either is fine; seeing one set does not
mean the other is missing.

If `user-data` and `network-config` are absent entirely, the settings were
never applied and the card must be rewritten.

**A caveat about `.local` names.** The config installs `avahi-daemon` on first
boot, which is what makes `gridhawk.local` resolve — and installing it needs
internet. So on the very first boot the Pi may be on the network and reachable
by IP address while its name still does not resolve. Find it by address if the
name fails.

## Step 3 — First boot

1. Eject the card from the Mac, put it in the **Pi's** slot (underside, near the
  corner).
2. Connect the **real power supply**, not your laptop.
3. Wait. First boot takes 2–3 minutes — it resizes the filesystem and joins
  Wi-Fi. The green light flickers while it works.

The Pi has no screen, so it will look like nothing is happening. That is normal.

## Step 4 — Connect from your Mac

```bash
ping -c 3 gridhawk.local
```

Once it answers:

```bash
ssh <your-username>@gridhawk.local
```

Say `yes` to the fingerprint prompt, enter your password, and you are on the Pi.
Everything after this runs **on the Pi**, not the Mac.

**If** `gridhawk.local` **does not resolve**, find it by address instead:

```bash
# on the Mac -- your network is 192.168.8.x
arp -a | grep -i "b8:27:eb\|dc:a6:32\|e4:5f:01\|d8:3a:dd"
```

Those prefixes belong to Raspberry Pi hardware. Then `ssh <your-username>@192.168.8.<n>`.

## Step 5 — Update and install what GridHawk needs

```bash
sudo apt update && sudo apt full-upgrade -y      # a few minutes
sudo apt install -y git rtl-sdr tcpdump
```

- **git** — to fetch the code
- **rtl-sdr** — drivers and `rtl_power`, which reads the radio spectrum
- **tcpdump** — captures network packets

Python 3 is already installed, and GridHawk needs nothing beyond it.

## Step 6 — Stop Linux from stealing the SDR

Your dongle is technically a TV tuner, and Linux ships a TV driver that grabs it
on sight. That driver has to be pushed out of the way:

```bash
echo 'blacklist dvb_usb_rtl28xxu' | sudo tee /etc/modprobe.d/blacklist-rtl.conf
sudo reboot
```

Wait a minute, then `ssh <your-username>@gridhawk.local` again.

## Step 7 — Get GridHawk

```bash
cd ~
git clone https://github.com/ltmcoding/GridHawk.git
cd GridHawk
make test
```

You should see **70 tests pass** across three suites. That confirms Python and
the whole codebase work on the Pi before any hardware is involved.

## Step 8 — Prove the software works with no hardware at all

```bash
python3 demo/rf_monitor.py baseline --replay demo/fallback/rf_baseline.csv \
    --baseline-file /tmp/b.json

python3 demo/rf_monitor.py monitor --replay demo/fallback/rf_two_radios.csv \
    --baseline-file /tmp/b.json
```

The first records where the "authorised" radio sits. The second should report
**two carriers** and flag the one it does not recognise.

If that works, the Pi is fully set up. Everything from here is hardware.

## Step 9 — Plug in the SDR

Attach the RTL-SDR to a **blue USB 3 port** (the Pi 5 has two blue, two black).

```bash
rtl_test -t
```

Expect something like `Found 1 device(s): 0: Realtek, RTL2838UHIDIR`. Press
Ctrl-C after a few seconds.

- `No supported devices found` → unplug and replug; confirm step 6 ran.
- `usb_claim_interface error -6` → the TV driver still has it; recheck step 6.

Now look at real radio noise:

```bash
rtl_power -f 433.85M:434.00M:250 -i 1 -e 10 /tmp/air.csv
python3 -c "
from collectors.rf import parse_rtl_power, find_carriers
sweeps = parse_rtl_power('/tmp/air.csv')
print(f'{len(sweeps)} sweeps captured')
for i, s in enumerate(sweeps[:3]):
    print(f'  sweep {i}: {len(s)} bins, {len(find_carriers(s))} carriers')
"
```

With no transmitter running you should see **0 carriers** — just noise. That is
the correct answer, and it is your false-positive check on real air.

Attach the dipole antenna from the kit; it improves sensitivity considerably.

---



## Common problems


| Symptom                         | Cause                    | Fix                                                        |
| ------------------------------- | ------------------------ | ---------------------------------------------------------- |
| Random freezes, corrupted files | underpowered             | use a 27 W supply, not a laptop port                       |
| `gridhawk.local` not found      | mDNS, or Pi not on Wi-Fi | find it via `arp -a`; recheck the Wi-Fi password in Imager |
| Pi never appears on the network | Wi-Fi details wrong      | re-flash the card; the settings are baked in at write time |
| `Permission denied` on SSH      | wrong username           | it is the one you set in Imager, not `pi`                  |
| `rtl_test` finds nothing        | TV driver holding it     | step 6, then reboot                                        |
| Card write fails                | bad reader or card       | try a different reader                                     |
| Everything is slow              | Class 10 card            | expected; fine for this work                               |


**A note on heat.** The Pi 5 runs hot and slows itself down to cope. Continuous
spectrum sweeping is exactly the kind of sustained load that triggers it. Check
with `vcgencmd measure_temp` — anything past 80 °C means you want a heatsink or
the official active cooler.

---



## Where to go next

The Pi is now ready to be the site monitor. Continue in
[DEMO.md](DEMO.md), which covers flashing the transmitters, the address map, the
inventory, and the demo script itself.

You can do all of DEMO.md in `--replay` mode today, without a single radio, and
it uses exactly the same detection code. Worth doing once before the hardware
arrives, so the only new variable on the day is the radio itself.