package main

import (
	"fmt"
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

func TestKeyPair(t *testing.T) {
	keyPair1, err := crypto.GenerateKeyPair()
	fmt.Printf("PAIR 1 PUBLIC: %x\n", keyPair1.PublicKey)
	if err != nil {
		t.Fatal("Error generating key pair!")
	}
	keyPair2, err := crypto.GenerateKeyPair()
	fmt.Printf("PAIR 2 PUBLIC: %x\n", keyPair2.PublicKey)
	if err != nil {
		t.Fatal("Error generating key pair!")
	}

	sharedKey1, err := crypto.DeriveSharedKey(keyPair1.PrivateKey, keyPair2.PublicKey)
	if err != nil {
		t.Fatal("Error deriving shared key for key pair 1!")
	}

	sharedKey2, err := crypto.DeriveSharedKey(keyPair2.PrivateKey, keyPair1.PublicKey)
	if err != nil {
		t.Fatal("Error deriving shared key for key pair 2!")
	}

	if string(sharedKey1) != string(sharedKey2) {
		t.Fatal("Derived shared keys do not match!")
	}
	t.Logf("Shared Key 1: %x\n", sharedKey1)
	t.Logf("Shared Key 2: %x\n", sharedKey2)
}
