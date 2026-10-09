# Security Status

NetPaste is a personal tool. Its custom protocol has **not** been audited, and
it has known weaknesses, listed below. Run the server only on networks you
trust (e.g. a host-only or VPN interface), and treat it as a convenience tool,
not a security boundary.

Findings below were checked against the code in this repository and refer to
`server/NetPaste-Windows.ps1` (the only server in active use) unless noted.

## Protocol v2: pairing and authentication

Protocol v2 is implemented in `client/netpaste.py` and
`server/NetPaste-Windows.ps1` only. The Linux and macOS servers and
`client/np-client.ps1` still speak v1 and **cannot talk to the v2 client**.

1. **Handshake.** The client sends its `client_id` and an ephemeral DH public
   key; the server answers with its `server_id`, its ephemeral DH public key,
   and whether it has a pairing for that client. Both compute
   `dh_key = SHA256(shared value)` and a transcript binding both ids and both
   public keys to `dh_key`.
2. **Pairing (once per client/server pair, `netpaste --pair` / `nppair`).**
   The client first sends only a hash (commitment) of its DH public key and
   reveals the key after the server has sent its own, so neither side, nor a
   man-in-the-middle, can pick a key after seeing the other's to steer the
   code. Both ends derive a 6-digit code from the transcript. The server shows it in
   a Yes/No dialog, the client shows it in the terminal, and the user confirms
   on **both** sides that they match. Each side then stores
   `secret = HMAC(dh_key, transcript)`. The secret is derived, never sent, and
   a man-in-the-middle produces different codes on each end. The server's
   approval is encrypted under the new session key, proving it derived the
   same secret.
3. **Every connection after that.** Both sides derive
   `session_key = HMAC(secret, transcript)`. The client proves it holds the
   secret by sending an `auth` message encrypted under that key; the server
   replies under the same key. A man-in-the-middle without the secret cannot
   derive either side's key, so the handshake fails. Keys stay ephemeral per
   connection (forward secrecy for recorded sessions).
4. **Per-pair secrets.** The server keeps one secret per `client_id`
   (`%APPDATA%\NetPaste\pairings.json`); the client keeps one per `server_id`
   (`~/.config/netpaste/pairings.json`). Clients cannot impersonate each other,
   and clearing pairings on the server (tray menu) revokes clients.
5. **No unauthenticated commands.** The server only dispatches messages
   decrypted with an authenticated session key. Plaintext messages are refused
   unless the server runs with `-NoEncrypt`.

Only an explicit `--pair` from a terminal starts pairing. Normal sends, the
MCP tools, `get_text` and `get_file` refuse to run against a server they are
not paired with, so a forged "not paired" reply cannot trigger pairing.

## Fixed in v2

| Former issue | Status |
|---|---|
| Plaintext commands accepted without authentication | **Fixed**: dispatch requires an authenticated session key (or explicit `-NoEncrypt`); unencrypted data after the handshake is rejected |
| Shared secret sent on every connection over unauthenticated DH | **Fixed**: the secret is mixed into the key derivation and never sent |
| Trust-on-first-use: server stored whatever secret arrived first | **Fixed**: pairing needs the user to confirm a matching code on both ends |
| One secret shared by all clients and servers | **Fixed**: per client/server pair |
| DH shared value, session key, and private key prefixes printed to the console | **Fixed**: debug output removed |
| Secret compared with non-constant-time `-eq` | **Gone**: authentication is by successful decryption under the derived key, no comparison |
| Linux client: config directory not `0700`, chmod after write | **Fixed**: directory `0700`, file created `0600` before writing |

## Known issues

### High

**1. No message integrity (AES-256-CBC without a MAC).**
Ciphertext can be modified in transit without detection (CBC bit-flipping).
Authentication of the `auth` message relies on the decrypted JSON being
well-formed, which is weaker than a MAC.
*Fix:* use an AEAD cipher — AES-256-GCM or ChaCha20-Poly1305.

**2. No replay protection within a connection.**
Messages carry no nonce or counter. Each connection derives a fresh key, so a
recorded session cannot be replayed on a new connection, but nothing inside a
connection orders or de-duplicates messages.
*Fix:* AEAD with a per-message counter nonce.

### Medium / Low

**3. Listener binds all interfaces** (`IPAddress::Any`). With v2 an
unauthenticated peer can no longer run commands, but it can still open
connections and trigger a pairing dialog.
*Fix:* bind to the interface the client connects through.

**4. Secret storage at rest.**
- Windows: `pairings.json` is plaintext with an owner-only ACL (inheritance
  disabled). Not encrypted with DPAPI.
- Linux client: `0600` file in a `0700` directory.
- Anyone who obtains one side's `pairings.json` can impersonate either end of
  that pair (symmetric secrets; no pinned public keys).

**5. A pairing can be half-completed.** If the user approves on the server but
answers "no" in the client terminal (or the reverse), only one side stores the
pairing. Re-run `--pair`. With a man-in-the-middle the codes differ, so a user
who compares them rejects on both ends.

**6. Key exchange primitive.** Finite-field DH over RFC 3526 group 14
(2048-bit MODP) is still acceptable but slow and large compared with X25519.
A modernization item, not a vulnerability.

## Recommended direction

The custom handshake is now authenticated, but it is still custom. If NetPaste
gains more clients or platforms, replace it with an established construction —
mutual TLS 1.3 with pinned self-signed certificates, or a Noise Protocol
handshake (`XXpsk` / `IKpsk`) — which also brings AEAD framing and replay
protection.

## What has been tested

| Component | Status |
|---|---|
| Python client (`client/netpaste.py`), CLI on Linux/WSL → Windows server | **Tested, in use** (protocol v1) |
| Python client as MCP server for Claude Code (Linux) | **Tested, in use** (protocol v1) |
| Windows PowerShell server (`server/NetPaste-Windows.ps1`) | **Tested, in use** (protocol v1) |
| Shell aliases (`client/.zshrc.np`), zsh | **Tested, in use** |
| Protocol v2 handshake, pairing, auth | Tested end to end with the real client against the server's PowerShell functions under `pwsh` on Linux; **not yet run on Windows** |
| `get_text` / `get_file` (server → client), Windows server only | New, not yet verified end to end on Windows |
| Python client on macOS or native Windows | Untested |
| Linux Python server (`server/NetPaste-Linux.py`) | **Untested**; protocol v1 only |
| macOS Swift server (`server/NetPaste-macOS.swift`) | **Untested**; protocol v1 only |
| PowerShell client (`client/np-client.ps1`) | **Untested**; protocol v1 only |
