# USB Event Sentinel

**Physical hardware threat interceptor.** A local daemon that listens for physical USB insertion, virtualizes the device's metadata, has Claude Code analyze the mounted filesystem for threats, and toggles local firewall rules in response.

**B2B security angle:** enterprise threat protection against malicious local hardware — rubber duckies, exfil drives, HID-masquerading devices — caught at the moment of insertion, with an AI analyst in the loop.

## How it works

```
USB inserted
   │
   ▼
┌─────────────┐   ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│  Capture    │──▶│  Virtualization  │──▶│  Claude Analysis │──▶│  Firewall        │
│  (sources)  │   │  fingerprint +   │   │  claude -p →     │   │  pf anchor rules │
│  sim | real │   │  fs manifest     │   │  Verdict JSON    │   │  dry-run|enforce │
└─────────────┘   └──────────────────┘   └──────────────────┘   └──────────────────┘
        │                  │                     │                      │
        └──────────────────┴───── event bus ─────┴──────────────────────┘
                                     │
                          ┌──────────┴──────────┐
                          │  Terminal TUI       │
                          │  Web SOC dashboard  │
                          └─────────────────────┘
```

- **Adapter-pattern capture:** `SimulatedUsbSource` (fixture drives, runs anywhere, keyless) and `MacUsbSource` (`diskutil activity` stream + `system_profiler` diffing). A Linux `udev` source drops in later for the Raspberry Pi keyfob build.
- **Virtualization:** device identity → stable fingerprint; mounted filesystem → bounded manifest (hashes, entropy, red-flag files).
- **Analysis:** headless Claude Code (`claude -p`) returns a strict JSON verdict; an offline heuristic engine takes over when Claude is unavailable.
- **Response:** pf firewall anchor ruleset (anti-exfil outbound lockdown). Dry-run by default; `--enforce` loads it via `pfctl` with auto-revert on detach/TTL.

## Build stages

- [x] **Stage 1 — Scaffold & tech stack:** TS daemon shell, typed event bus, config, zero-dep runtime (Node native type stripping)
- [ ] **Stage 2 — USB capture layer:** simulated fixture drives + real macOS source
- [ ] **Stage 3 — Metadata virtualization & filesystem fingerprinting**
- [ ] **Stage 4 — Claude Code analysis pipeline** (+ offline heuristic fallback)
- [ ] **Stage 5 — Firewall responder:** pf dry-run / `--enforce` / auto-revert / quarantine
- [ ] **Stage 6 — Terminal ops TUI**
- [ ] **Stage 7 — Web security-ops dashboard** (WebSocket live feed)
- [ ] **Stage 8 — Attack scenarios, hardening & Raspberry Pi path**

## Run

Requires Node ≥ 23.6 (runs TypeScript natively — no build step, no dependencies yet).

```bash
npm run dev              # simulated mode, dry-run firewall (default, safe anywhere)
npm run dev:real         # watch actual USB insertions (macOS)
npm run dev:enforce      # real mode + live pfctl rules (needs sudo — Stage 5+)
```

Flags: `--mode=simulated|real` · `--enforce` · `--quarantine` · `--no-claude`

## Roadmap beyond v1

Raspberry Pi deployment with physical USB keyfobs / hardware security keys: the `UsbSource` adapter swaps `MacUsbSource` for a `udev`-based Linux source; the pf responder swaps for `nftables`. Same bus, same pipeline, same dashboards.
