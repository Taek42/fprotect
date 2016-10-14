package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/twofish"
)

const (
	numVerificationBytes = 6
)

// harden will take a string password, improve the security slightly, and
// return a key.
func harden(password string) []byte {
	// Require fprotect-specific rainbow tables to crack passwords.
	password = "simplefprotectsalt-ylhhqgibiyeh" + password

	// Harden with 25,000 rounds of sha256.
	hashedPW := sha256.Sum256([]byte(password))
	for i := 0; i < 25e3; i++ {
		hashedPW = sha256.Sum256(hashedPW[:])
	}
	return hashedPW[:]
}

// encryptBytes will take a key and some text and return the encrypted version
// of that text.
func encryptBytes(key []byte, plaintext []byte) ([]byte, error) {
	// Prepend 6 empty bytes to the plaintext so that the decryptor can verify
	// that decryption happened correctly.
	zeroes := make([]byte, numVerificationBytes)
	fulltext := append(zeroes, plaintext...)

	// Create the cipher and aead.
	twofishCipher, err := twofish.NewCipher(key)
	if err != nil {
		return nil, errors.New("unable to create twofish cipher: " + err.Error())
	}
	aead, err := cipher.NewGCM(twofishCipher)
	if err != nil {
		return nil, errors.New("unable to create AEAD: " + err.Error())
	}

	// Generate the nonce.
	nonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, errors.New("failed to generate entropy for nonce: " + err.Error())
	}

	// Encrypt the data and return.
	return aead.Seal(nonce, nonce, fulltext, nil), nil
}

// decryptBytes will take a key and a ciphertext, and return the plaintext
// version of the ciphertext.
func decryptBytes(key []byte, ciphertext []byte) ([]byte, error) {
	// Create the cipher and aead.
	twofishCipher, err := twofish.NewCipher(key)
	if err != nil {
		return nil, errors.New("unable to create twofish cipher: " + err.Error())
	}
	aead, err := cipher.NewGCM(twofishCipher)
	if err != nil {
		return nil, errors.New("unable to create AEAD: " + err.Error())
	}

	// Check for a nonce to prevent panics.
	if len(ciphertext) < aead.NonceSize()+numVerificationBytes {
		return nil, errors.New("input ciphertext is not long enough and cannot be decrypted")
	}

	// Decrypt the data, verify that the key is correct (with high
	// probability), and return.
	fulltext, err := aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], nil)
	if err != nil {
		return nil, errors.New("unable to decrypt data: " + err.Error())
	}
	zeroes := make([]byte, numVerificationBytes)
	if !bytes.Equal(zeroes, fulltext[:6]) {
		return nil, errors.New("key appears to be incorrect")
	}
	return fulltext[6:], nil
}
