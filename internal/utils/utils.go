package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/neozmmv/blindspot/internal/crypto"
)

type Identity struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

var blindspotDirOverride string

func SetBlindspotDir(dir string) {
	blindspotDirOverride = dir
}

func GetBlindspotDir() string {
	if blindspotDirOverride != "" {
		return blindspotDirOverride
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(homeDir, ".blindspot")
}

func WriteIdentity(privateKey, publicKey []byte) error {
	if IdentityExists() {
		return nil // identity already exists, do nothing
	}
	if len(privateKey) != 32 || len(publicKey) != 32 {
		return fmt.Errorf("invalid key length: private and public keys must be 32 bytes")
	}
	dir := GetBlindspotDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	identity := Identity{
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey),
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey),
	}

	data, err := json.Marshal(identity)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(dir, "identity.json"), data, 0600)
}

func IdentityExists() bool {
	path := filepath.Join(GetBlindspotDir(), "identity.json")
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func ReadIdentity() (privateKey, publicKey []byte, err error) {
	path := filepath.Join(GetBlindspotDir(), "identity.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading identity: %w", err)
	}
	var identity Identity
	if err := json.Unmarshal(data, &identity); err != nil {
		return nil, nil, fmt.Errorf("error parsing identity: %w", err)
	}
	privateKey, err = base64.StdEncoding.DecodeString(identity.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding private key: %w", err)
	}
	publicKey, err = base64.StdEncoding.DecodeString(identity.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding public key: %w", err)
	}
	return privateKey, publicKey, nil
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
