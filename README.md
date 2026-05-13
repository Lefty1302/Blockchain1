# Lab 1 – Proof of Work over IPv8

This repository contains a complete Python client for **CS4160 Lab 1**.

## Quick Start

This repository uses the uv package manager. Install it if you don’t have it yet:

```powershell
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
# Windows
irm https://astral.sh/uv/install.ps1 | iex
```

**Then run the client:**

```powershell
uv lock
uv sync
uv run lab1 --email netid@tudelft.nl --github-url https://github.com/vesk4000/BitConnect
```

## Project layout

- `src/lab1_pow_ipv8/pow.py` – PoW construction, validation and mining loop
- `src/lab1_pow_ipv8/validation.py` – email/url/nonce validation
- `src/lab1_pow_ipv8/protocol.py` – IPv8 message payloads (`msg_id=1` and `msg_id=2`)
- `src/lab1_pow_ipv8/client.py` – community + peer filtering + submission flow
- `src/lab1_pow_ipv8/main.py` – CLI entrypoint
- `tests/test_pow.py` – local tests for PoW correctness

## Setup (UV)

UV manages the virtual environment and installs dependencies for you.

```powershell
uv lock
uv sync
```

### Pre-commit (format on commit)

```powershell
uv sync
uv run pre-commit install
```

Black uses spaces (not tabs) by design.

## Usage

Run the client from the project root:

```powershell
uv run python -m lab1_pow_ipv8.main --email vmitev@tudelft.nl --github-url https://github.com/vesk4000/BitConnect
```

Or use the shorthand script:

```powershell
uv run lab1 --email vmitev@tudelft.nl --github-url https://github.com/vesk4000/BitConnect
```

### Useful flags

- `--key-file lab1_identity.pem` to persist/reuse your private key
- `--difficulty 28` (default for lab server)
- `--mine-only` mine and print nonce, but do not submit
- `--nonce <N>` provide an existing nonce (skip mining when used with `--submit-only`)
- `--submit-only --nonce <N>` skip mining and only submit
- `--timeout 120` seconds to wait for server reply
- `--no-canonicalize-email` send/hash the email exactly as typed
- `--debug-peers` log discovered peers and public keys while searching
- `--bootstrap host:port` manually seed discovery (can be repeated)
- `--walk-peers 50` adjust random-walk target peers
- `--walk-timeout 5` adjust random-walk timeout seconds

## Notes and pitfalls

- Nonce encoding is 8-byte **big-endian** binary (not decimal text).
- PoW input is exactly: `email + "\n" + github_url + "\n" + nonce_u64_be`.
- The client ignores responses from peers whose public key does not match the given server key.
- Keep your `.pem` file safe: this is your identity for later labs.

## Lab 2 – Coordinated Group Signing Prep Phase

Lab 2 requires fast UDP coordination between three teammates. The **prep phase** sets this up before the timed challenge.

### Quick Start

**Step 1: Extract your public key** (share with teammates via WhatsApp)

```powershell
uv run lab2-prep --print-pubkey --pem lab1_identity.pem
```

**Step 2: Run prep with all three team members**

All three nodes run simultaneously (same command on each machine with different `--udp-port`):

```powershell
uv run lab2-prep \
  --udp-port 5000 \
  --peer-pubkey <TEAMMATE_A_PUBKEY> \
  --peer-pubkey <TEAMMATE_B_PUBKEY> \
  --test-udp
```

IPv8 automatically discovers teammates' UDP endpoints. Each node just needs:
- Its own UDP port (different for each: 5000, 5001, 5002)
- The two teammates' public keys (same for all three)

Expected output: canonical order, peer map, and ✓ connectivity test.

**Optional: Manual endpoint mode** (if you know IPs ahead of time)

```powershell
uv run lab2-prep \
  --udp-port 5000 \
  --peer 192.168.1.10:5001 --peer-pubkey <PUBKEY_A> \
  --peer 192.168.1.11:5002 --peer-pubkey <PUBKEY_B> \
  --test-udp
```

### Lab 2 Prep Options

- `--print-pubkey` – Extract pubkey from PEM, print & exit
- `--pem <path>` – PEM file (default: `lab1_identity.pem`)
- `--udp-port <int>` – Local UDP port (required)
- `--udp-host <host>` – UDP host/IP to advertise (default: auto-detect local LAN IPv4; use `127.0.0.1` for same-machine testing)
- `--peer-pubkey <hex>` – Teammate pubkey hex (repeatable, use 1 for two-person testing or 2 for the full group)
- `--peer <host:port>` – (Optional) Bypass IPv8 discovery and manually specify endpoint (repeatable)
- `--test-udp` – Run UDP connectivity test (ping/pong)
- `--debug` – Enable debug logging

### How it works

**Default mode (IPv8 auto-discovery):**
1. Extracts your Ed25519 public key from Lab 1 PEM file
2. Advertises your UDP endpoint over IPv8
3. Uses IPv8 peer discovery to find teammates and request their UDP endpoints
4. Sends UDP hello/ping packets to every discovered teammate endpoint
5. Sorts all three pubkeys lexicographically → canonical order
6. Uses canonical order to assign fixed submitters: Round 1 → sorted[0], Round 2 → sorted[1], Round 3 → sorted[2]
7. Reports peer map and submitter assignments

**Manual mode (optional `--peer`):**
- Use `--peer host:port` to manually specify teammates' endpoints instead of auto-discovery
- Useful if IPv8 discovery isn't working or for known static IPs

---

## Troubleshooting

- If no server response arrives, ensure your packet is sent with IPv8 authenticated messaging (`ez_send`, as implemented).
- If you get invalid hash rejections, confirm you are hashing the exact same email/URL strings you submit.
- If logs show `Known peers: none yet`, your network isn't discovering peers; try a different network or use `--bootstrap host:port`
  from a TA/classmate to seed discovery.
- On Windows, the client auto-downloads the official libsodium MSVC bundle into `vendor/libsodium/` if the DLL is missing,
  and prepends that folder to `PATH` for the current process. This does **not** modify your system PATH.
- On macOS/Linux, the client first tries your system libsodium. If it's missing, you can either:
  - Install via your OS package manager (e.g. `brew install libsodium`, `apt install libsodium`)
  - Or set `LIBSODIUM_URL` to a direct archive URL that contains a prebuilt `libsodium.dylib` or `libsodium.so`.
- You can always point to an existing local folder with the library via `LIBSODIUM_DIR`.

**Lab 2 prep UDP connectivity issues:**
- Check all three nodes are running
- For two-person testing, pass the single teammate key once; do not duplicate it.
- If auto-detected UDP host is wrong, pass `--udp-host <your-lan-ip>`.
- Verify firewall allows UDP on the specified ports
- Confirm `--peer` addresses match where teammates are actually listening
- If using different machines, ensure they can reach each other (try `ping` first)

---
Hello!
