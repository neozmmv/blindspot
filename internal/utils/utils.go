package utils

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/neozmmv/blindspot/internal/crypto"
)

// IdentityPassphraseEnv is the environment variable holding the passphrase used to
// encrypt/decrypt the identity at rest. When set, new identities are stored
// encrypted and reading an encrypted identity requires it.
const IdentityPassphraseEnv = "BLINDSPOT_IDENTITY_PASSPHRASE"

// Identity is the on-disk identity file. It has two forms:
//
//   - plaintext (legacy): private_key + public_key, both base64.
//   - encrypted: encrypted=true, salt + ciphertext hold the scrypt salt and the
//     AES-256-GCM sealed private key; public_key stays in cleartext (it is public
//     anyway) so public-key-only operations don't need the passphrase.
type Identity struct {
	Encrypted  bool   `json:"encrypted,omitempty"`
	Salt       string `json:"salt,omitempty"`       // base64 scrypt salt (encrypted form)
	Ciphertext string `json:"ciphertext,omitempty"` // base64(nonce||AES-GCM ct) of the private key
	PrivateKey string `json:"private_key,omitempty"` // base64 (plaintext form only)
	PublicKey  string `json:"public_key"`            // base64; present in both forms
}

func GetBlindspotDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(homeDir, ".blindspot")
}

func identityPath() string {
	return filepath.Join(GetBlindspotDir(), "identity.json")
}

func identityPassphrase() []byte {
	return []byte(os.Getenv(IdentityPassphraseEnv))
}

// writeIdentityFile writes (and overwrites) the identity file. When passphrase is
// non-empty the private key is encrypted at rest; otherwise it is stored plaintext.
func writeIdentityFile(privateKey, publicKey, passphrase []byte) error {
	if len(privateKey) != 32 || len(publicKey) != 32 {
		return fmt.Errorf("invalid key length: private and public keys must be 32 bytes")
	}
	if err := os.MkdirAll(GetBlindspotDir(), 0700); err != nil {
		return err
	}

	identity := Identity{PublicKey: base64.StdEncoding.EncodeToString(publicKey)}
	if len(passphrase) > 0 {
		salt := make([]byte, crypto.IdentitySaltLen)
		if _, err := rand.Read(salt); err != nil {
			return err
		}
		key, err := crypto.DeriveKeyFromPassphrase(passphrase, salt)
		if err != nil {
			return err
		}
		sealed, err := crypto.EncryptBytes(key, privateKey) // nonce||ciphertext
		if err != nil {
			return err
		}
		identity.Encrypted = true
		identity.Salt = base64.StdEncoding.EncodeToString(salt)
		identity.Ciphertext = base64.StdEncoding.EncodeToString(sealed)
	} else {
		identity.PrivateKey = base64.StdEncoding.EncodeToString(privateKey)
	}

	data, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	return os.WriteFile(identityPath(), data, 0600)
}

// WriteIdentity creates the identity file if it does not already exist, encrypting
// it when a passphrase is configured via IdentityPassphraseEnv.
func WriteIdentity(privateKey, publicKey []byte) error {
	if IdentityExists() {
		return nil // identity already exists, do nothing
	}
	return writeIdentityFile(privateKey, publicKey, identityPassphrase())
}

func IdentityExists() bool {
	_, err := os.Stat(identityPath())
	return !os.IsNotExist(err)
}

func readIdentityFile() (*Identity, error) {
	data, err := os.ReadFile(identityPath())
	if err != nil {
		return nil, fmt.Errorf("error reading identity: %w", err)
	}
	var identity Identity
	if err := json.Unmarshal(data, &identity); err != nil {
		return nil, fmt.Errorf("error parsing identity: %w", err)
	}
	return &identity, nil
}

// ReadIdentity returns the identity's private and public keys, decrypting the
// private key when the file is stored encrypted (requiring IdentityPassphraseEnv).
func ReadIdentity() (privateKey, publicKey []byte, err error) {
	identity, err := readIdentityFile()
	if err != nil {
		return nil, nil, err
	}
	publicKey, err = base64.StdEncoding.DecodeString(identity.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding public key: %w", err)
	}

	if identity.Encrypted {
		passphrase := identityPassphrase()
		if len(passphrase) == 0 {
			return nil, nil, fmt.Errorf("identity is encrypted; set %s to unlock it", IdentityPassphraseEnv)
		}
		salt, err := base64.StdEncoding.DecodeString(identity.Salt)
		if err != nil {
			return nil, nil, fmt.Errorf("error decoding salt: %w", err)
		}
		key, err := crypto.DeriveKeyFromPassphrase(passphrase, salt)
		if err != nil {
			return nil, nil, err
		}
		sealed, err := base64.StdEncoding.DecodeString(identity.Ciphertext)
		if err != nil {
			return nil, nil, fmt.Errorf("error decoding ciphertext: %w", err)
		}
		privateKey, err = crypto.DecryptBytes(key, sealed)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt identity (wrong passphrase?): %w", err)
		}
		return privateKey, publicKey, nil
	}

	privateKey, err = base64.StdEncoding.DecodeString(identity.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding private key: %w", err)
	}
	return privateKey, publicKey, nil
}

// ReadPublicKey returns just the public key, which is stored in cleartext in both
// forms, so it never requires the passphrase.
func ReadPublicKey() ([]byte, error) {
	identity, err := readIdentityFile()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(identity.PublicKey)
}

// IsIdentityEncrypted reports whether the stored identity is encrypted at rest.
func IsIdentityEncrypted() (bool, error) {
	identity, err := readIdentityFile()
	if err != nil {
		return false, err
	}
	return identity.Encrypted, nil
}

// RewriteIdentity re-writes the existing identity, changing its at-rest protection:
// a non-empty newPassphrase encrypts it, an empty one stores it plaintext. It reads
// the current keys via ReadIdentity (which needs IdentityPassphraseEnv if the file
// is currently encrypted).
func RewriteIdentity(newPassphrase []byte) error {
	privateKey, publicKey, err := ReadIdentity()
	if err != nil {
		return err
	}
	return writeIdentityFile(privateKey, publicKey, newPassphrase)
}

func InitIdentity() (*crypto.KeyPair, error) {
	if IdentityExists() {
		return nil, fmt.Errorf("identity already exists")
	}
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("Error generating key pair: %v\n", err)
	}
	if err := WriteIdentity(keyPair.PrivateKey, keyPair.PublicKey); err != nil {
		return nil, fmt.Errorf("Error writing identity: %v\n", err)
	}
	return keyPair, nil
}
