package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

func GenerateKeyPair() (*KeyPair, error) {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, err
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func DeriveSharedKey(privateKey, peerPublicKey []byte) ([]byte, error) {
	return curve25519.X25519(privateKey, peerPublicKey)
}
