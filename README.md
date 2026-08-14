<img width=255 src='public/BLINDSPOT_BANNER.svg'>

# Blindspot

A P2P VPN and networking toolkit built on UDP hole punching with end-to-end encryption. Connect directly to peers without servers in the middle — traverses NAT and CGNAT automatically.

Peers find each other in one of two ways:

- **Serverless rooms over Tor** (`connect`, `chat`) — a room name and password derive a Tor onion address that every peer computes independently. Nothing is registered anywhere in advance, and there is no rendezvous server to trust or run.
- **A rendezvous server** (`rendezvous`) — the original flow, using a lightweight signaling server ([Rendezvous](https://github.com/neozmmv/rendezvous)) to exchange addresses.

Either way, discovery only ever exchanges UDP addresses and public keys — addresses each peer learns for itself from a public STUN server. Once peers have found each other, all traffic flows **directly** between them, encrypted end-to-end: it never passes through Tor or through any server.


## How it works

### Serverless rooms — `connect` / `chat`

A room is nothing but a name and a password. Both are fed through Argon2id to derive a Tor v3 onion service key, so every peer that knows the pair computes the **same** `.onion` address, with no DNS and no registry. Whoever arrives first publishes the service and hosts the room; everyone else finds them there and joins.

```
Peer A                        Tor                        Peer B
  |                            |                            |
  |-- Argon2id(name, password) → the same .onion address ----|
  |-- each discovers its own public IP via STUN -------------|
  |                            |                            |
  |-- publishes descriptor --->|                            |
  |   (first to arrive hosts)  |<-- fetches descriptor ------|
  |                            |                            |
  |<--- UDP addrs + static public keys, over the room API -->|
  |                            |                            |
  |<========= UDP hole punching (direct, not via Tor) ======>|
  |                            |                            |
  |<====== Noise IKpsk2 handshake (static keys pinned) =====>|
  |                            |                            |
  |<========= encrypted P2P traffic (direct) ==============>|
```

The room API the host serves ([`internal/roomserver`](internal/roomserver)) is the rendezvous server's peer-discovery API, trimmed to what the onion model needs. It has no password check of its own: reaching the service at all requires having derived the address, which requires knowing the name and password already.

**Hosting moves.** Because the address is derived, it never changes — so a client keeps talking to the same URL no matter who is behind it. Clients heartbeat the host every 45s; after three consecutive failures they hold an election staggered by join order, and the winner republishes the descriptor and takes over. Peers keep their live connections through a handover: only the discovery endpoint changes, not the UDP transport, the Noise sessions or the TUN device.

**One room, one mode.** A room is either a VPN room (`connect`) or a chat room (`chat`), decided by whoever hosts it first and fixed for the room's life. The two modes share no traffic types — one sends only tunnelled IP packets, the other only chat messages — so a peer arriving with the wrong command is refused outright, with an error naming the command that would work:

```
$ blindspot chat my-room "correct horse battery staple"
Error joining room: room "my-room" is already in use for VPN — join it with
"blindspot connect", or pick a different room name
```

The room that already exists always wins; the arriving peer never takes it over. Peers of different modes also commit to different Noise prologues, so even in the race where two of them publish the room at the same instant, the handshake between them fails rather than producing two peers that look connected and silently carry nothing.

**Expect it to be slow to start.** Deriving the key, bootstrapping Tor and publishing or fetching a descriptor was measured anywhere between ~28s and ~187s for the same code on the same machine. The commands print each step as it happens; `connect` waits up to 6 minutes before giving up.

### Rendezvous server — `rendezvous`

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

In both models, static public keys are exchanged through discovery (over TLS for the rendezvous server, inside the onion circuit for a room) and pinned **before** the handshake — so an on-path attacker who can see or tamper with the UDP traffic still cannot impersonate a peer. If both peers are on the same local network, Blindspot detects this and connects via local IP instead — no internet round-trip.


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

- **Static keys are pinned, not exchanged in the clear.** Unlike v1 (where the public key rode inside the `HELLO` packet), the static public key is *never* sent on the wire. Each peer publishes its key through discovery, and both sides pin the other's key before the handshake begins. This is what neutralises an on-path attacker: they cannot substitute their own key for a peer's.
- **Pre-shared key as a second factor.** The session password is stretched with **Argon2id** (64 MiB, 1 iteration, 4 lanes, salted with the session id) into a 32-byte PSK, mixed in at the `psk2` position. Against the rendezvous server it is genuine defense-in-depth: even if the server were compromised and published a forged static key, an attacker still could not complete the handshake without the password. In a room it is *not* an independent factor — the same password derives the onion address — but it still covers the case where the address leaks and the password does not. Password-less ("open") rendezvous sessions use a deterministic-but-public PSK, so authentication then rests entirely on the pinned static key.
- **Prologue binding.** The handshake prologue commits to the protocol version and session id (the room name, for rooms), so a handshake captured in one session or version can't be replayed into another. Chat peers commit to a distinct prologue, which is what makes a chat↔VPN session impossible rather than merely refused at discovery.

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

Downloads the latest release binary for your architecture (`amd64` or `arm64`), installs it to `/usr/local/bin`, and installs Tor through your package manager if it isn't already present.

> VPN mode requires `sudo` to create the TUN adapter — the `connect` command will tell you if you need it.

### Windows

```powershell
irm https://raw.githubusercontent.com/neozmmv/blindspot/master/scripts/install.ps1 | iex
```

Downloads the latest release binary to `%LOCALAPPDATA%\Microsoft\WindowsApps` (already in your PATH on Windows 10/11), and drops `tor.exe` from the Tor Project's Expert Bundle beside it.

> VPN mode requires administrator privileges — Blindspot requests elevation via UAC automatically.

### Via Go

```bash
go install github.com/neozmmv/blindspot@latest
```

> Requires Go 1.21+. The binary will be placed in `$GOPATH/bin`. Install Tor separately (see below) for the room commands.

### Build from source

```bash
git clone https://github.com/neozmmv/blindspot
cd blindspot
go build -o blindspot .
```

### Manual download

Pre-built binaries are also available directly on the [releases page](https://github.com/neozmmv/blindspot/releases).

### Tor

`connect` and `chat` run Tor as a subprocess — it is not linked into the binary. Blindspot looks for a bundled copy at `tor/tor` (or `tor\tor.exe`) next to the `blindspot` executable first, then for one on `PATH`. The install scripts above set this up for you, and `blindspot update` installs Tor too if the machine still has none. A manual install or `go install` needs a system Tor:

```bash
sudo apt install tor      # or dnf/pacman/zypper/apk
```

Blindspot spawns its own instance with its own control port and does not use the system `tor` service, so that service can stay disabled. `blindspot rendezvous` does not need Tor at all.


## Usage

### VPN mode — `connect` / `disconnect`

Creates a virtual network adapter (`blindspot`, `10.x.x.x/8`) and connects every peer in the room into a mesh. Once connected, peers see each other as if they were on the same LAN — file sharing, RDP, ping, and any other protocol work transparently.

```bash
# both peers run the same thing; whoever is first hosts the room
sudo blindspot connect my-room "correct horse battery staple"
```

```
Deriving room address and starting Tor; this can take a minute...
  starting Tor
  looking for an existing host at 7fd2...onion
  no host found. publishing 7fd2...onion
  hosting room at 7fd2...onion
Connected to room "my-room"
```

The command returns once the daemon is up and keeps running in the background. To disconnect:

```bash
blindspot disconnect
```

**Windows:** the UAC prompt appears automatically if not running as administrator.

**Linux:** must run with `sudo`.

The room name must be at least 4 characters and the password at least 8. Those are minimums, not advice — see [Security](#security).

#### Flags

```
    --up-mbit N   Force a fixed upload cap in Mbit/s (0 = automatic)
```

---

### VPN mode via a rendezvous server — `rendezvous`

The server-based alternative to `connect`. Faster to start (seconds, not minutes) and needs no Tor, at the cost of depending on a server that sees your UDP address.

```bash
# peer A — creates a password-protected session and connects
sudo blindspot rendezvous -s my-network -p mypassword -n

# peer B — joins the session
sudo blindspot rendezvous -s my-network -p mypassword
```

`blindspot disconnect` ends it, exactly as with `connect`.

#### Flags

```
-s, --session    Session ID (required)
-p, --password   Session password (required, min 8 chars when creating)
-n, --new        Create a new password-protected session
-H, --hostname   Custom rendezvous server
    --insecure   Allow a plaintext http:// rendezvous (NOT recommended)
    --up-mbit N  Force a fixed upload cap in Mbit/s (0 = automatic)
```

The rendezvous must be reached over `https://` — a plaintext `http://` URL is refused
unless you explicitly pass `--insecure`. The session password is sent to the rendezvous
in the request body / `Authorization` header, never in the URL query string.

---

### Chat mode — `chat`

Encrypted P2P chat between everyone in a room. Same serverless Tor discovery as `connect`, but with no TUN device — so no `sudo`, no UAC, and nothing to clean up afterwards.

```bash
# both peers run the same thing
blindspot chat my-room "correct horse battery staple"
```

```
Deriving room address and starting Tor; this can take a minute...
  starting Tor
  looking for an existing host at 7fd2...onion
  joining host at 7fd2...onion
Public addr: 203.0.113.45:51820
Peer addr: 198.51.100.12:51820
Waiting for peers...
198.51.100.12:51820 joined!
Connected! Type to chat.
> hey
[21:04:11] - [198.51.100.12:51820]: hey back
```

Messages are broadcast to every connected peer. Type `/quit` or `/exit`, or press Ctrl+C, to leave. The chat runs in the foreground and takes no flags — the room name and password are the whole interface.

A chat room and a VPN room are separate things even under the same name and password: `chat` refuses a room that `connect` is hosting, and vice versa. See [One room, one mode](#serverless-rooms--connect--chat).

---

### List peers — `list`

Prints all peers currently connected to the active VPN session, showing their virtual IP and public address.

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

### Encrypting your identity at rest — `identity`

Your private key lives at `~/.blindspot/identity.json`. To encrypt it at rest, set a
passphrase in the `BLINDSPOT_IDENTITY_PASSPHRASE` environment variable; new identities
are then stored encrypted (scrypt + AES-256-GCM), and reading the private key requires
the passphrase.

```
blindspot identity status      # show whether the identity is encrypted
blindspot identity encrypt     # encrypt using BLINDSPOT_IDENTITY_PASSPHRASE
blindspot identity decrypt     # revert to plaintext (needs the passphrase)
```

> Note: the VPN daemon relaunches elevated via UAC, which does not inherit a
> shell-session environment variable — set `BLINDSPOT_IDENTITY_PASSPHRASE` as a
> persistent user/machine variable (e.g. `setx`) for the elevated daemon to see it.

---

### Persistent settings — `config`

```
blindspot config               # show current settings
blindspot config up-mbit 80    # force a fixed 80 Mbit/s upload cap
blindspot config up-mbit 0     # back to automatic
```

Stored in `~/.blindspot/config.json` and applied by every future connect, CLI or tray. Upload shaping is automatic by default: the tunnel stays uncapped until real packet loss appears. Only set a fixed cap if that misbehaves on your link.

---

### Other commands

```
blindspot update      # download and install the latest release
blindspot version     # print the installed version
```


## Signaling server

Only `blindspot rendezvous` uses one. The public server at `https://rendezvous.enzogp.dev` is the default; you can self-host using the [Rendezvous](https://github.com/neozmmv/rendezvous) project, or pass your own with `-H`.

It only sees UDP addresses and public keys during the handshake — it never touches actual P2P traffic. `connect` and `chat` do not use it at all.


## Security

- **Handshake** — Noise `IKpsk2` (X25519 + AES-256-GCM + SHA-256, the WireGuard cipher suite). Static public keys are pinned from discovery and never sent on the wire, so an on-path attacker cannot impersonate a peer.
- **Forward secrecy** — The Noise handshake mixes fresh ephemeral keypairs into every session. Compromise of a device's long-term static private key does **not** reveal traffic from past sessions.
- **Second factor** — The session password is stretched with Argon2id into a pre-shared key mixed in at the `psk2` position, so a compromised rendezvous still cannot forge a session on a password-protected group.
- **Encryption** — AES-256-GCM. Each transport packet uses a monotonic per-direction counter as its nonce, and the packet header (version, type, counter) is authenticated as AEAD associated data.
- **Anti-replay** — An RFC 6479 sliding-window filter (2048-packet window) drops replayed or out-of-window packets, checked only after authentication succeeds.
- **Identity** — Each device has a persistent X25519 keypair stored locally, optionally encrypted at rest (scrypt + AES-256-GCM). The public key also determines the device's virtual IP in VPN mode, and tunnelled packets are reverse-path filtered against it.
- **No relay** — Traffic never passes through any server after the handshake, and never through Tor. Only binary ciphertext is visible on the wire.

**Room passwords carry the whole room.** A room's security rests on password entropy alone. Guessing is an entirely offline exercise — derive a candidate address, ask Tor whether a descriptor exists — and nothing rate-limits it. The key derivation is deliberately expensive to make each guess cost something (Argon2id, 512 MiB, ~200ms per attempt, paid once by you and once per guess by an attacker), but that only buys a factor, not safety: use a passphrase, not a password. The 4-character name and 8-character password minimums are a floor against typos, not a recommendation.

Room name and password are also positional arguments, so they land in your shell history and in the process list of a multi-user machine. Treat them accordingly.

## Roadmap

- [x] UDP hole punching (traverses NAT and CGNAT)
- [x] Same-network detection → local IP fallback
- [x] Noise `IKpsk2` handshake (X25519 + AES-256-GCM + SHA-256)
- [x] Static public keys pinned from discovery (no key-in-the-clear)
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
- [x] Adaptive upload shaping (fixed cap via `config up-mbit`)
- [x] System tray UI (Windows)
- [x] Serverless rooms — onion address derived from name + password
- [x] Automatic host failover when the room's host disappears
- [x] Serverless chat over the same rooms
- [ ] macOS TUN support
- [ ] Reliable delivery (ACK + retransmission)
