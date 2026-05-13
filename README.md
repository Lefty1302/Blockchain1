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
- `src/lab2_relay_race/` - Lab 2 prep, signed UDP, and relay race client
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

## Lab 2 - Coordinated Group Signing Relay

Lab 2 uses IPv8 for server messages and teammate discovery, then signed direct UDP for the timed relay race.

### Quick Start

**Step 1: Extract your public key** 

```powershell
uv run lab2-prep --print-pubkey --pem lab1_identity.pem
```

Then make a new *.txt file in ./pubkeys with your public key

**Step 2: Test UDP connectivity**

All three nodes can run the UDP test simultaneously with different `--udp-port` values:

```powershell
uv run lab2-prep --pem lab1_identity.pem --udp-port 5000 --test-udp
```

`lab2-prep` loads the explicit role order from `lab2_team.json`, discovers teammate UDP endpoints over IPv8, and tests UDP ping/pong reachability. It does not write a handoff state file.

**Step 3: Run the relay race**

All three nodes run the relay command at the same time:

```powershell
uv run lab2-race --pem lab1_identity.pem --udp-port 5000
```

The relay command performs its own discovery phase, waits for the Lab 2 server, then enters the active phase. Node A registers the group and sends `GroupReady`; Node B and C wait for it. Submitter order is fixed by `lab2_team.json`:

- Round 1 / Node A: `pubkeys/vesk.txt`
- Round 2 / Node B: `pubkeys/miro.txt`
- Round 3 / Node C: `pubkeys/dany.txt`

**Optional: Manual endpoint mode** (if you know IPs ahead of time)

```powershell
uv run lab2-prep \
  --udp-port 5000 \
  --peer 192.168.1.10:5001 --peer-pubkey <PUBKEY_A> \
  --peer 192.168.1.11:5002 --peer-pubkey <PUBKEY_B> \
  --test-udp
```

### Lab 2 Prep Options

- `--print-pubkey` - Extract pubkey from PEM, print and exit
- `--pem <path>` - PEM file (default: `lab1_identity.pem`)
- `--team-config <path>` - Explicit A/B/C role config (default: `lab2_team.json`)
- `--udp-port <int>` - Local UDP port (required)
- `--peer-pubkey <hex>` - Teammate pubkey override for partial-team tests
- `--peer <host:port>` - Optional manual endpoint for UDP tests
- `--test-udp` - Run UDP connectivity test
- `--debug` - Enable debug logging

### Lab 2 Race Options

- `--pem <path>` - PEM file for the Lab 1 key
- `--team-config <path>` - Explicit A/B/C role config
- `--udp-port <int>` - Local UDP port for signed relay traffic
- `--discovery-timeout <seconds>` - Teammate discovery timeout
- `--server-timeout <seconds>` - Lab 2 server discovery timeout
- `--debug` - Enable debug logging

### How it works

**Default mode (IPv8 auto-discovery):**
1. Extracts your Ed25519 public key from Lab 1 PEM file
2. Loads teammate public keys and A/B/C roles from `lab2_team.json`
3. Joins the Lab 2 IPv8 community and uses peer discovery to find teammates' UDP endpoints (only peers whose pubkey matches a teammate are accepted)
4. Uses high-range custom IPv8 endpoint messages (`200`, `201`) to avoid server ID conflicts
5. Uses signed UDP messages (`210`-`214`) for race coordination
6. Builds bundle signatures in the exact registration order from `lab2_team.json`

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
- Verify firewall allows UDP on the specified ports
- Confirm `--peer` addresses match where teammates are actually listening
- If using different machines, ensure they can reach each other (try `ping` first)

