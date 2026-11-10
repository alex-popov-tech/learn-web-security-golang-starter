package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

type EncryptedPayload struct {
	Nonce, AuthTag, Ciphertext []byte
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	tagStart := len(sealed) - aead.Overhead()
	return EncryptedPayload{
		Ciphertext: sealed[:tagStart],
		Nonce:      nonce,
		AuthTag:    sealed[tagStart:],
	}, nil
}

// reject payloads without a 12-byte nonce and 16-byte authentication tag
// authenticate and decrypt the reconstructed sealed value
// return an error when the payload was modified or the key is wrong
func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if payload.Nonce == nil || len(payload.Nonce) != 12 || payload.AuthTag == nil ||
		len(payload.AuthTag) != 16 {
		return nil, errors.New("invalid serialized encrypted payload")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealed := append(append([]byte{}, payload.Ciphertext...), payload.AuthTag...)
	return aead.Open(nil, payload.Nonce, sealed, nil)
}
