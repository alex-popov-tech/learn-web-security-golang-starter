package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	memory     = uint32(19 * 1024)
	iterations = uint32(2)
	threads    = uint8(1)
	keyLen     = 32
	MaxLength  = 128
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derivedKey := argon2.IDKey([]byte(password), salt, iterations, memory, threads, keyLen)

	return encodeArgon2idHash(argon2idHash{
		version:     argon2.Version,
		memoryKiB:   uint32(memory),
		iterations:  iterations,
		parallelism: threads,
		salt:        salt,
		derivedKey:  derivedKey,
	}), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}

	if strings.HasPrefix(encodedHash, "$argon2id$") {
		parsedHash, ok := parseArgon2idHash(encodedHash)
		if !ok || parsedHash.version != argon2.Version {
			return false
		}
		candidateHash := argon2.IDKey(
			[]byte(password),
			parsedHash.salt,
			parsedHash.iterations,
			parsedHash.memoryKiB,
			parsedHash.parallelism,
			keyLen,
		)
		return subtle.ConstantTimeCompare(candidateHash, parsedHash.derivedKey) == 1
	}
	expectedHash, ok := decodeLegacyHash(encodedHash)
	if !ok {
		return false
	}
	candidateHash := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
}

func NeedsRehash(hash string) bool {
	parsed, ok := parseArgon2idHash(hash)
	if !ok {
		_, ok := decodeLegacyHash(hash)
		return ok
	}
	if parsed.iterations != iterations {
		return true
	}
	if parsed.memoryKiB != memory {
		return true
	}
	if parsed.parallelism != threads {
		return true
	}
	if parsed.version != argon2.Version {
		return true
	}
	if len(parsed.derivedKey) != keyLen {
		return true
	}
	return false
}
