# Blindspot

A P2P networking tool and protocol built on UDP hole punching with end-to-end encryption. Connect directly to peers without servers in the middle — traverses NAT and CGNAT automatically.

> ⚠️ **Work in progress.** Core functionality works. VPN mode (tun/tap) is not yet implemented.

---

## How it works

Blindspot uses a lightweight signaling server ([Rendezvous](https://github.com/neozmmv/rendezvous)) only to exchange UDP addresses between peers. Once the connection is established, all traffic flows directly — encrypted, peer-to-peer, with no server in the middle.

```
Peer A                  Rendezvous                  Peer B
  |                         |                          |
  |-- discovers public IP via STUN (Google) ----------|
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

If both peers are on the same local network, Blindspot detects this automatically and connects via local IP instead — no internet round-trip.

---

## Blindspot Protocol

Blindspot defines its own binary protocol over UDP:

```
Packet types:
  0x01  HELLO       → hole punching + X25519 public key exchange
  0x02  PING        → keepalive
  0x03  PONG        → keepalive response
  0x04  DATA        → encrypted payload (AES-256-GCM)
  0x05  DEAD        → graceful disconnect
  0x06  ACK         → acknowledgement (reserved)
```

Each packet starts with a 1-byte type identifier followed by the payload. The `HELLO` packet carries a 32-byte X25519 public key — both peers exchange keys during hole punching and derive a shared AES-256 key via ECDH. All subsequent `DATA` packets are encrypted with AES-256-GCM with a random nonce per packet.

**Identity** is a persistent X25519 keypair stored at `~/.blindspot/identity.json`, generated on first run.

---

## Installation

### Download

Pre-built binaries for Windows, Linux, and Linux ARM64 are available on the [releases page](https://github.com/neozmmv/blindspot/releases). No installation required.

### Build from source

```bash
git clone https://github.com/neozmmv/blindspot
cd blindspot
go build -o blindspot .
```

---

## Usage

### Chat

```bash
# peer A — creates a session
blindspot chat -s my-session

# peer B — joins the same session
blindspot chat -s my-session
```

With a custom rendezvous server:

```bash
blindspot chat -s my-session -H https://my-rendezvous.example.com
```

With a password-protected session:

```bash
# peer A — creates with password
blindspot chat -s my-session -p secret -c

# peer B — joins with password
blindspot chat -s my-session -p secret
```

### Flags

```
-s, --session    Session ID (required)
-p, --password   Session password
-c, --create     Create a password-protected session
-H, --hostname   Custom rendezvous server (default: https://rendezvous.enzogp.dev)
```

---

## Signaling server

The public rendezvous server at `https://rendezvous.enzogp.dev` is available by default. You can self-host your own using the [Rendezvous](https://github.com/neozmmv/rendezvous) project.

The signaling server only sees UDP addresses during the handshake — it never touches the actual P2P traffic.

---

## Security

- **Key exchange** — X25519 ECDH. Public keys are exchanged in the clear during hole punching; the shared secret never leaves either device.
- **Encryption** — AES-256-GCM with a random nonce per packet. Integrity and authenticity are guaranteed by the GCM authentication tag.
- **Identity** — Each device has a persistent X25519 keypair. The public key fingerprint can be used to verify peer identity out of band.
- **No relay** — Traffic never passes through any server after the handshake. Verified with Wireshark — only binary ciphertext is visible on the wire.

> **Known limitation:** The current handshake does not provide forward secrecy. If a device's private key is compromised, past sessions could be decrypted. This will be addressed in a future protocol version via ephemeral keypairs.

---

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
- [ ] Forward secrecy via ephemeral keypairs
- [ ] Reliable delivery (ACK + retransmission)
- [ ] VPN mode via tun/tap interface
- [ ] IP derivation from public key (mesh networking)
- [ ] Multi-peer mesh sessions
- [ ] File transfer
- [ ] System tray UI