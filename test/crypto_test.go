package main

import (
	"testing"

	"github.com/neozmmv/blindspot/internal/crypto"
)

func TestAES(t *testing.T) {
	key, err := crypto.GenerateAESKey()
	t.Logf("KEY: %x\n", key)
	if err != nil {
		t.Fatal("Error generating AES key!")
	}
	plaintext := []byte("Hello, World!")
	ciphertext, err := crypto.EncryptBytes(key, plaintext)
	if err != nil {
		t.Fatal("Error encrypting bytes!")
	}
	t.Logf("Ciphertext: %v\n", ciphertext)
	decrypted, err := crypto.DecryptBytes(key, ciphertext)
	if err != nil {
		t.Fatal("Error decrypting bytes!")
	}
	if string(decrypted) != string(plaintext) {
		t.Fatal("Decrypted text does not match original plaintext!")
	}

	t.Logf("Decrypted: %v\n", string(decrypted))
}
