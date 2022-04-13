package hashing

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const entryFormatting = "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"

type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var (
	DefaultHashingParams = &Params{
		Memory:      64 * 1024,
		Iterations:  6,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}

	ErrInvalidEntryFormatting = errors.New("the encoded entry is not in the correct format")
	ErrIncompatibleAlgorithm  = errors.New("algorithm should be argon2id")
	ErrIncompatibleVersion    = errors.New("incompatible version of argon2id")
)

func GenerateHashFromPassword(password string, params *Params) (string, error) {
	salt, err := generateRandomBytes(params.SaltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt, params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	entry := fmt.Sprintf(
		entryFormatting,
		argon2.Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		encodedSalt,
		encodedHash,
	)

	return entry, nil
}

func ComparePasswordAndHash(password, entry string) (match bool, err error) {
	params, salt, hash, err := decodeEntry(entry)
	if err != nil {
		return false, err
	}

	calculatedHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	if bytes.Compare(hash, calculatedHash) == 0 {
		return true, nil
	}
	return false, nil
}

func CalculateSha256(input string) string {
	hash := sha256.New()
	hash.Write([]byte(input))
	encodedHash := hex.EncodeToString(hash.Sum(nil))

	return encodedHash
}

func generateRandomBytes(byteCount uint32) ([]byte, error) {
	randomBytes := make([]byte, byteCount)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	return randomBytes, nil
}

func decodeEntry(entry string) (params *Params, salt, hash []byte, err error) {
	entryValues := strings.Split(entry, "$")
	if len(entryValues) != 6 {
		return nil, nil, nil, ErrInvalidEntryFormatting
	}

	var hashingAlgorithm string
	_, err = fmt.Sscanf(entryValues[1], "%s", &hashingAlgorithm)
	if err != nil {
		return nil, nil, nil, err
	}
	if hashingAlgorithm != "argon2id" {
		return nil, nil, nil, ErrIncompatibleAlgorithm
	}

	var version int
	_, err = fmt.Sscanf(entryValues[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	params = &Params{}
	_, err = fmt.Sscanf(
		entryValues[3],
		"m=%d,t=%d,p=%d",
		&params.Memory,
		&params.Iterations,
		&params.Parallelism,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(entryValues[4])
	if err != nil {
		return nil, nil, nil, err
	}
	params.SaltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(entryValues[5])
	if err != nil {
		return nil, nil, nil, err
	}
	params.KeyLength = uint32(len(hash))

	return params, salt, hash, nil
}
