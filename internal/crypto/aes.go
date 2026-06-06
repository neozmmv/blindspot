package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"
)

func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256
	if _, err := rand.Reader.Read(key); err != nil {
		fmt.Println("Error generating AES key! ", err)
		return nil, err
	}
	return key, nil
}

// this doesnt call the AES key schedule on every packet, (it was like 70k calls per 100MB)
// AEAD wraps a cipher.AEAD with a thread-safe counter-based nonce.
// creating it once per shared key avoids rebuilding the AES key schedule
// on every packet (which was the main CPU bottleneck).
type AEAD struct {
	gcm     cipher.AEAD
	counter atomic.Uint64
	base    [4]byte // random session prefix for the 12-byte nonce
}

func NewAEAD(key []byte) (*AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	a := &AEAD{gcm: gcm}
	if _, err := io.ReadFull(rand.Reader, a.base[:]); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *AEAD) nonce() []byte {
	n := make([]byte, 12)
	copy(n[:4], a.base[:4])                                // 4 random bytes, fixed per session
	binary.LittleEndian.PutUint64(n[4:], a.counter.Add(1)) // 8-byte monotonic counter
	return n
}

func (a *AEAD) Encrypt(plaintext []byte) []byte {
	nonce := a.nonce()
	return a.gcm.Seal(nonce, nonce, plaintext, nil)
}

func (a *AEAD) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := a.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return a.gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}

// EncryptBytes and DecryptBytes are kept for compatibility but build a
// fresh cipher each call — prefer AEAD for hot paths.
func EncryptBytes(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func DecryptBytes(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}
