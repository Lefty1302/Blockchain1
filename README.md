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

## Troubleshooting

- If no server response arrives, ensure your packet is sent with IPv8 authenticated messaging (`ez_send`, as implemented).
- If you get invalid hash rejections, confirm you are hashing the exact same email/URL strings you submit.
- If logs show `Known peers: none yet`, your network isn’t discovering peers; try a different network or use `--bootstrap host:port`
  from a TA/classmate to seed discovery.
- On Windows, the client auto-downloads the official libsodium MSVC bundle into `vendor/libsodium/` if the DLL is missing,
  and prepends that folder to `PATH` for the current process. This does **not** modify your system PATH.
- On macOS/Linux, the client first tries your system libsodium. If it’s missing, you can either:
  - Install via your OS package manager (e.g. `brew install libsodium`, `apt install libsodium`)
  - Or set `LIBSODIUM_URL` to a direct archive URL that contains a prebuilt `libsodium.dylib` or `libsodium.so`.
- You can always point to an existing local folder with the library via `LIBSODIUM_DIR`.

---
Hello!
