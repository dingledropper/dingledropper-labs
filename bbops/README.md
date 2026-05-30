# bbops — turning the M4 Air into an always-on bug-bounty recon/fuzzing rig

This turns an idle Apple-Silicon MacBook Air (fanless) into a headless, always-on
compute node that you drive remotely from your phone, a browser, or another
laptop. It runs **scope-gated** recon + vulnerability scanning on a schedule and
pings you when something *new* shows up, plus an optional **thermal-throttled**
fuzzing setup.

> ⚠️ **Authorization is not optional.** Only ever run this against assets that a
> bug-bounty / VDP program *explicitly lists as in scope*, or systems you own.
> Automated scanning of anything else can get you banned from programs and may be
> illegal. The pipeline refuses to run without an explicit in-scope allowlist and
> filters every target against it — keep it that way.

---

## The shape of it

```
  Phone / browser / laptop                 M4 MacBook Air (headless, always-on)
  ─────────────────────────                ────────────────────────────────────
  • Claude Code (web/app)  ──ssh / Tailscale──▶  • recon.sh on a launchd schedule
  • read alerts                                  • subfinder → httpx → nuclei
  • triage + write reports                       • diff vs last run → notify on NEW
                                                 • optional throttled fuzzing
                                                 • results committed to git
```

The Air does the grinding; you do the judgement. Recon is network-bound and
bursty, which suits a fanless machine well. Heavy fuzzing is the only sustained-CPU
piece and is deliberately throttled.

---

## One-time setup (run ON the Air)

1. Copy this repo onto the Air (or `git clone` it).
2. Run the setup script:
   ```sh
   cd bbops
   ./setup-mac.sh
   ```
   It installs Homebrew + the ProjectDiscovery toolchain, updates nuclei
   templates, and prints the exact commands to enable remote login + keep-awake.
3. **Fill in the two blanks** (see below).
4. Install the schedule:
   ```sh
   ./setup-mac.sh --install-schedule
   ```

### Blank #1 — your scope (required)

```sh
cp scope.txt.example scope.txt
cp scope-exclude.txt.example scope-exclude.txt
```

Put the **root domains you are authorized to test** in `scope.txt`, one per line.
Put anything to never touch (out-of-scope subdomains, third parties) in
`scope-exclude.txt`. `recon.sh` exits immediately if `scope.txt` is empty.

### Blank #2 — where alerts go (optional but recommended)

Set one of these in your shell env (or in `~/bbops/.env`):

```sh
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
# or
export TELEGRAM_BOT_TOKEN="123:abc"
export TELEGRAM_CHAT_ID="123456"
```

No webhook configured → alerts just go to `~/bbops/alerts.log`.

---

## Driving it remotely (the "from my phone" part)

The clean, no-port-forwarding way is **Tailscale** (free for personal use):

1. `brew install --cask tailscale` (done by setup script), then sign in.
2. Do the same on your phone/laptop — they join the same private network.
3. From anywhere: `ssh youruser@<air-tailscale-name>`.

Keep-awake + headless (Apple Silicon sleeps with the lid shut by default):

```sh
sudo systemsetup -setremotelogin on        # enable SSH
sudo pmset -c sleep 0                       # don't sleep on power adapter
caffeinate -s &                             # belt-and-suspenders while plugged in
```

Run it plugged in, lid open or on a stand with airflow. See THERMAL below.

---

## Daily loop (your <5 hrs/week)

- You get an alert: "3 new live hosts, 1 new nuclei finding (medium)."
- SSH in, look at `~/bbops/runs/<date>/`, validate the finding by hand.
- If real and in-scope → write it up and submit to the program.
- That's it. The rig keeps running.

---

## Thermal notes (fanless = respect it)

- Recon/scan loads are bursty and network-bound — fine for the Air.
- `recon.sh` caps nuclei concurrency and runs at low priority (`nice`).
- Fuzzing (`fuzz/`) is the sustained-CPU part: it leaves cores free, runs niced,
  and you choose how many jobs. Don't run all-core 24/7.
- Elevate the laptop for airflow; a cheap stand or a small USB fan helps a lot.
- If the chassis is too hot to touch comfortably, dial down `NUCLEI_CONCURRENCY`
  and fuzzing `JOBS`.

---

## Files

| File | What it does |
|------|--------------|
| `setup-mac.sh` | Installs toolchain, configures keep-awake, installs schedule |
| `recon.sh` | Scope-gated subfinder → httpx → nuclei, diffs vs last run |
| `notify.sh` | Sends alerts via Discord / Telegram / log |
| `scope.txt.example` | Template for your authorized root domains |
| `scope-exclude.txt.example` | Template for never-touch targets |
| `launchd/com.dingledropper.recon.plist` | The schedule (every 6h) |
| `fuzz/` | Thermal-throttled libFuzzer runner + a worked example |
