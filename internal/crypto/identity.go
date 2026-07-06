package crypto

import "golang.org/x/crypto/scrypt"

// scrypt parameters for deriving the identity-encryption key from a passphrase.
// N=32768 (2^15), r=8, p=1 is the interactive-login baseline recommended by the
// scrypt author and OWASP.
const (
	scryptN         = 1 << 15
	scryptR         = 8
	scryptP         = 1
	scryptKeyLen    = 32
	IdentitySaltLen = 16
)

// DeriveKeyFromPassphrase derives a 32-byte AES-256 key from a passphrase and
// salt using scrypt. Used to encrypt the on-disk identity (the static private key)
// at rest. Unlike the Noise PSK this is not a network second factor — it only
// protects the key file if the disk is read by someone without the passphrase.
func DeriveKeyFromPassphrase(passphrase, salt []byte) ([]byte, error) {
	return scrypt.Key(passphrase, salt, scryptN, scryptR, scryptP, scryptKeyLen)
}
