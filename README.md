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
  |<========= X25519 handshake + AES-256-GCM ========>|
  |                         |                          |
  |<========= encrypted P2P traffic =================>|
```

If both peers are on the same local network, Blindspot detects this and connects via local IP instead — no internet round-trip.


## Blindspot Protocol

Blindspot defines its own binary protocol over UDP. Each packet starts with a 1-byte type identifier followed by the payload.

```
Packet types:
  0x01  HELLO       → hole punching + X25519 public key exchange
  0x02  PING        → keepalive
  0x03  PONG        → keepalive response
  0x04  DATA        → encrypted chat payload (AES-256-GCM)
  0x05  DEAD        → graceful disconnect notification
  0x06  ACK         → acknowledgement (reserved)
  0x07  TUN         → encrypted IP packet (VPN mode, AES-256-GCM)
```

**Handshake:** The `HELLO` packet carries a 32-byte X25519 public key. Both peers exchange keys during hole punching and derive a shared AES-256 key via ECDH. All `DATA` and `TUN` packets are encrypted with AES-256-GCM using a random nonce per packet.

**`DATA` vs `TUN`:** Chat messages use `PacketData (0x04)` and VPN traffic uses `PacketTun (0x07)`. They are encrypted identically but kept separate so the two modes can coexist on the same session without interference.

**Virtual IPs:** Each peer derives its VPN address deterministically from its public key: `SHA256(publicKey)[0:3]` → `10.x.x.x/8`. No server involvement — every peer can compute every other peer's virtual IP from the keys exchanged during handshake.

**Identity** is a persistent X25519 keypair stored at `~/.blindspot/identity.json`, generated on first run.


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

Creates a virtual network adapter (`blindspot`, `10.x.x.x/8`) and connects all peers on the same session into a mesh. Once connected, peers see each other as if they were on the same LAN — file sharing (SMB), RDP, ping, and any other protocol work transparently.

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
```

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

- **Key exchange** — X25519 ECDH. Public keys are exchanged in the clear during hole punching; the shared secret never leaves either device.
- **Encryption** — AES-256-GCM with a random nonce per packet. Integrity and authenticity are guaranteed by the GCM authentication tag.
- **Identity** — Each device has a persistent X25519 keypair stored locally. The public key also determines the device's virtual IP in VPN mode.
- **No relay** — Traffic never passes through any server after the handshake. Only binary ciphertext is visible on the wire.

> **Known limitation:** The current handshake does not provide forward secrecy. If a device's private key is compromised, past sessions could be decrypted. This will be addressed in a future version via ephemeral keypairs.

## Roadmap

- [x] UDP hole punching (traverses NAT and CGNAT)
- [x] Same-network detection → local IP fallback
- [x] X25519 key exchange during handshake
- [x] AES-256-GCM encryption
- [x] Persistent device identity
- [x] Keepalive + disconnect detection
- [x] Graceful disconnect (DEAD packet)
- [x] Password-protected sessions
- [x] Binary protocol with typed packets
- [x] Multi-peer mesh sessions
- [x] VPN mode — Windows (WinTUN) and Linux
- [x] Virtual IP derived from public key
- [x] Background daemon with UAC auto-elevation (Windows)
- [x] `disconnect` command with graceful shutdown
- [ ] macOS TUN support
- [ ] Forward secrecy via ephemeral keypairs
- [ ] Reliable delivery (ACK + retransmission)
- [x] File transfer (`send` / `receive` over the VPN tunnel)
- [ ] System tray UI
