package crypto

import "golang.org/x/crypto/argon2"

// Argon2id parameters for deriving the pre-shared key from the session password.
// These follow OWASP's Argon2id guidance (64 MiB, 1 iteration, 4 lanes).
const (
	pskArgonTime    = 1
	pskArgonMemory  = 64 * 1024 // KiB → 64 MiB
	pskArgonThreads = 4
	pskLen          = 32
)

// DerivePSK derives a 32-byte pre-shared key from the session password, salted
// with the session id, using Argon2id.
//
// In the Noise IKpsk2 handshake this PSK is a SECOND FACTOR: the primary anchor
// of identity is the peer's static public key, distributed by the trusted
// rendezvous over TLS. The PSK's job is defense-in-depth — if the rendezvous is
// ever compromised and publishes a forged static key, an attacker still cannot
// complete the handshake without also knowing the password-derived PSK.
//
// For password-less ("open") sessions the password is empty. The result is still
// deterministic and identical on both peers, but it carries no secret: anyone who
// knows the session id can derive it. In that mode authentication rests entirely
// on the rendezvous-pinned static public key.
func DerivePSK(password, sessionId string) []byte {
	return argon2.IDKey([]byte(password), []byte(sessionId), pskArgonTime, pskArgonMemory, pskArgonThreads, pskLen)
}
