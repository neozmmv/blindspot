# Blindspot

A P2P VPN and networking toolkit built on UDP hole punching with end-to-end encryption. Connect directly to peers without servers in the middle — traverses NAT and CGNAT automatically.


## How it works

Blindspot uses a lightweight signaling server ([Rendezvous](https://github.com/neozmmv/rendezvous)) only to exchange UDP addresses between peers. Once connected, all traffic flows directly — encrypted, peer-to-peer, with no server in the middle.

```
Peer A                  Rendezvous                  Peer B
  |                         |                          |
  |-- discovers public IP via STUN ------------------|
  |-- registers UDP addr -->|                          |
  |                         |<-- registers UDP addr ---|
  |<-- peer B's addr -------|-- peer A's addr -------->|
  |                         |                          |
  |<========= UDP hole punching (direct) ============>|
  |                         |                          |
  |<===== Noise IKpsk2 handshake (static keys ========>|
  |          pinned from rendezvous over TLS)          |
  |                         |                          |
  |<========= encrypted P2P traffic =================>|
```

Static public keys are exchanged through the rendezvous over TLS and pinned **before** the handshake — so an on-path attacker who can see or tamper with the UDP traffic still cannot impersonate a peer. If both peers are on the same local network, Blindspot detects this and connects via local IP instead — no internet round-trip.


## Blindspot Protocol (v2)

Blindspot defines its own binary protocol over UDP. As of **protocol version 2**, every packet on the wire is:

```
[Version:1][Type:1][Body...]
```

`Version` is `0x02`. A packet carrying any other version byte is dropped — peers never silently downgrade.

```
Outer packet types:
  0x10  HANDSHAKE_INIT  → Noise IKpsk2 message 1 (initiator → responder)
  0x11  HANDSHAKE_RESP  → Noise IKpsk2 message 2 (responder → initiator)
  0x12  PUNCH           → empty NAT hole-punch keepalive during the handshake
  0x04  DATA            → encrypted chat payload
  0x07  TUN             → encrypted tunnelled IP packet (VPN mode)
  0x08  CONTROL         → encrypted control message (inner opcode)

Inner control opcodes (plaintext inside an encrypted CONTROL packet):
  0x01  PING            → keepalive
  0x02  PONG            → keepalive response
  0x03  DEAD            → graceful disconnect notification
```

**Handshake — Noise IKpsk2.** v2 replaces the hand-rolled X25519/ECDH exchange with the [Noise Protocol Framework](https://noiseprotocol.org/) `IKpsk2` pattern, using the same cipher suite as WireGuard: **X25519** for Diffie–Hellman, **AES-256-GCM** for the AEAD, and **SHA-256** for hashing/HKDF. The peer with the lexicographically smaller static public key becomes the Noise initiator, so the role is decided deterministically without negotiation.

- **Static keys are pinned, not exchanged in the clear.** Unlike v1 (where the public key rode inside the `HELLO` packet), the static public key is *never* sent on the wire. Each peer publishes its key to the trusted rendezvous over TLS, and both sides pin the other's key before the handshake begins. This is what neutralises an on-path attacker: they cannot substitute their own key for a peer's.
- **Pre-shared key as a second factor.** The session password is stretched with **Argon2id** (64 MiB, 1 iteration, 4 lanes, salted with the session id) into a 32-byte PSK, mixed in at the `psk2` position. It is defense-in-depth: even if the rendezvous were compromised and published a forged static key, an attacker still could not complete the handshake without the password. Password-less ("open") sessions use a deterministic-but-public PSK, so authentication then rests entirely on the pinned static key.
- **Prologue binding.** The handshake prologue commits to the protocol version and session id, so a handshake captured in one session or version can't be replayed into another.

**Transport packets.** After the handshake, `DATA`, `TUN`, and `CONTROL` packets share one authenticated, anti-replay-protected channel. Each transport body is:

```
[Counter:8][AEAD ciphertext]
```

The AEAD's additional data (AAD) is the 10-byte cleartext header `[Version][Type][Counter]`, so the type and counter are authenticated — flipping either in transit fails the tag. The 64-bit `Counter` is a monotonic, per-direction value that doubles as the AEAD nonce (separate cipherstates secure each direction). The receiver enforces an **RFC 6479 sliding-window anti-replay filter** (2048-packet window, matching WireGuard) that is consulted *only after* a packet authenticates, so a forged packet can never advance the window or punch a hole in it.

**`DATA` vs `TUN` vs `CONTROL`:** Chat messages use `DATA (0x04)`, VPN traffic uses `TUN (0x07)`, and keepalive/disconnect signalling rides inside encrypted `CONTROL (0x08)` packets. Because control traffic is encrypted and replay-protected like everything else, there is no cleartext keepalive or "peer dead" packet an attacker could forge (as there was in v1).

**Virtual IPs:** Each peer derives its VPN address deterministically from its public key: `SHA256(publicKey)[0:3]` → `10.x.x.x/8`. No server involvement — every peer can compute every other peer's virtual IP from the pinned static keys. Tunnelled packets are also reverse-path filtered: a `TUN` packet whose source IP doesn't match the sender's virtual IP is dropped.

**Identity** is a persistent X25519 keypair stored at `~/.blindspot/identity.json`, generated on first run. It can be encrypted at rest — see the [`identity`](#encrypting-your-identity-at-rest--identity) command.


## Installation

### Linux

```bash
curl -fsSL https://raw.githubusercontent.com/neozmmv/blindspot/master/scripts/install.sh | bash
```

Downloads the latest release binary for your architecture (`amd64` or `arm64`) and installs it to `/usr/local/bin`.

> VPN mode requires `sudo` to create the TUN adapter — the `connect` command will tell you if you need it.

### Windows

```powershell
irm https://raw.githubusercontent.com/neozmmv/blindspot/master/scripts/install.ps1 | iex
```

Downloads the latest release binary and installs it to `%LOCALAPPDATA%\Microsoft\WindowsApps`, which is already in your PATH on Windows 10/11.

> VPN mode requires administrator privileges — Blindspot requests elevation via UAC automatically.

### Via Go

```bash
go install github.com/neozmmv/blindspot@latest
```

> Requires Go 1.21+. The binary will be placed in `$GOPATH/bin`.

### Build from source

```bash
git clone https://github.com/neozmmv/blindspot
cd blindspot
go build -o blindspot .
```

### Manual download

Pre-built binaries are also available directly on the [releases page](https://github.com/neozmmv/blindspot/releases).


## Usage

### VPN mode — `connect` / `disconnect`

Creates a virtual network adapter (`blindspot`, `10.x.x.x/8`) and connects all peers on the same session into a mesh. Once connected, peers see each other as if they were on the same LAN — file sharing, RDP, ping, and any other protocol work transparently.

```bash
# peer A — creates a password-protected session and connects
blindspot connect -s my-network -p mypassword -n

# peer B — joins the session
blindspot connect -s my-network -p mypassword
```

The command returns immediately after the daemon starts. To disconnect:

```bash
blindspot disconnect
```

**Windows:** UAC prompt appears automatically if not running as administrator.

**Linux:** Must run with `sudo`:
```bash
sudo blindspot connect -s my-network -p mypassword -n
```

#### Flags

```
-s, --session    Session ID (required)
-p, --password   Session password (required, min 8 chars when creating)
-n, --new        Create a new password-protected session
-H, --hostname   Custom rendezvous server
    --insecure   Allow a plaintext http:// rendezvous (NOT recommended)
```

The rendezvous must be reached over `https://` — a plaintext `http://` URL is refused
unless you explicitly pass `--insecure`. The session password is sent to the rendezvous
in the request body / `Authorization` header, never in the URL query string.

---

### Encrypting your identity at rest — `identity`

Your private key lives at `~/.blindspot/identity.json`. To encrypt it at rest, set a
passphrase in the `BLINDSPOT_IDENTITY_PASSPHRASE` environment variable; new identities
are then stored encrypted (scrypt + AES-256-GCM), and reading the private key requires
the passphrase.

```
blindspot identity status     # show whether the identity is encrypted
blindspot identity encrypt     # encrypt using BLINDSPOT_IDENTITY_PASSPHRASE
blindspot identity decrypt     # revert to plaintext (needs the passphrase)
```

> Note: the `connect` daemon relaunches elevated via UAC, which does not inherit a
> shell-session environment variable — set `BLINDSPOT_IDENTITY_PASSPHRASE` as a
> persistent user/machine variable (e.g. `setx`) for the elevated daemon to see it.

---

### List peers — `list`

Prints all peers currently connected to the active session, showing their virtual IP and public address.

```bash
blindspot list
```

```
VIRTUAL IP          PUBLIC ADDRESS
10.142.31.7         203.0.113.45:51820
10.88.201.14        198.51.100.12:51820
```

Requires an active session. Returns `No active session.` if no daemon is running.

---

### Your virtual IP — `ip`

Prints your own virtual IP address without needing an active connection. Useful for sharing your address with peers before or during a session.

```bash
blindspot ip
# 10.x.x.x
```

---

### File transfer — `send` / `receive`

Send files directly to a peer over the VPN tunnel — no credentials, no server, no setup. Traffic is encrypted end-to-end by the VPN layer.

```bash
# receiver runs first
blindspot receive
# Waiting for file on 10.x.x.x:28125...

# sender
blindspot send 10.x.x.x path/to/file.zip
# Sending file.zip (4823041 bytes) to 10.x.x.x...
# Sent 4823041 bytes.
```

Files are saved to `~/Downloads` by default. Use `--here` to save to the current directory instead:

```bash
blindspot receive --here
```

If the peer is not listening, the sender waits 5 seconds and prints a clear message rather than hanging.

---

### Chat mode — `chat`

Encrypted P2P chat directly between peers. No VPN adapter required.

```bash
# peer A — creates a session (no password)
blindspot chat -s my-session

# peer B — joins
blindspot chat -s my-session
```

With a password-protected session:

```bash
# peer A — creates with password
blindspot chat -s my-session -p secret -c

# peer B — joins with password
blindspot chat -s my-session -p secret
```

#### Flags

```
-s, --session    Session ID (required)
-p, --password   Session password
-c, --create     Create a password-protected session
-H, --hostname   Custom rendezvous server
```


## Signaling server

The public rendezvous server at `https://rendezvous.enzogp.dev` is used by default. You can self-host using the [Rendezvous](https://github.com/neozmmv/rendezvous) project.

The signaling server only sees UDP addresses during the handshake — it never touches actual P2P traffic.


## Security

- **Handshake** — Noise `IKpsk2` (X25519 + AES-256-GCM + SHA-256, the WireGuard cipher suite). Static public keys are pinned from the trusted rendezvous over TLS and never sent on the wire, so an on-path attacker cannot impersonate a peer.
- **Forward secrecy** — The Noise handshake mixes fresh ephemeral keypairs into every session. Compromise of a device's long-term static private key does **not** reveal traffic from past sessions.
- **Second factor** — The session password is stretched with Argon2id into a pre-shared key mixed in at the `psk2` position, so a compromised rendezvous still cannot forge a session on a password-protected group.
- **Encryption** — AES-256-GCM. Each transport packet uses a monotonic per-direction counter as its nonce, and the packet header (version, type, counter) is authenticated as AEAD associated data.
- **Anti-replay** — An RFC 6479 sliding-window filter (2048-packet window) drops replayed or out-of-window packets, checked only after authentication succeeds.
- **Identity** — Each device has a persistent X25519 keypair stored locally, optionally encrypted at rest (scrypt + AES-256-GCM). The public key also determines the device's virtual IP in VPN mode, and tunnelled packets are reverse-path filtered against it.
- **No relay** — Traffic never passes through any server after the handshake. Only binary ciphertext is visible on the wire.

## Roadmap

- [x] UDP hole punching (traverses NAT and CGNAT)
- [x] Same-network detection → local IP fallback
- [x] Noise `IKpsk2` handshake (X25519 + AES-256-GCM + SHA-256)
- [x] Static public keys pinned from the rendezvous (no key-in-the-clear)
- [x] Forward secrecy via Noise ephemeral keypairs
- [x] Argon2id pre-shared key as a second factor
- [x] RFC 6479 sliding-window anti-replay
- [x] Persistent device identity
- [x] Encrypted identity at rest (scrypt + AES-256-GCM)
- [x] Keepalive + disconnect detection (encrypted CONTROL channel)
- [x] Graceful disconnect (encrypted DEAD control message)
- [x] Password-protected sessions
- [x] Versioned binary protocol with typed packets
- [x] Multi-peer mesh sessions
- [x] VPN mode — Windows (WinTUN) and Linux
- [x] Virtual IP derived from public key + reverse-path filtering
- [x] Background daemon with UAC auto-elevation (Windows)
- [x] `disconnect` command with graceful shutdown
- [x] File transfer (`send` / `receive` over the VPN tunnel)
- [ ] macOS TUN support
- [ ] Reliable delivery (ACK + retransmission)
- [ ] System tray UI
