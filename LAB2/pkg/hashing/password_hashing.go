package hashing

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	encodedEntryFormatting = "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
	encodedEntryDelimiter  = "$"
)

var (
	ErrInvalidEncodedEntry   = errors.New("the encoded entry is not in the correct format")
	ErrIncompatibleAlgorithm = errors.New("algorithm should be argon2id")
	ErrIncompatibleVersion   = errors.New("incompatible version of argon2id")
)

type HashingParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func GenerateHashFromPassword(password string, p *HashingParams) (encodedEntry string, err error) {
	salt, err := generateRandomBytes(p.saltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	encodedEntry = fmt.Sprintf(
		encodedEntryFormatting,
		argon2.Version,
		p.memory,
		p.iterations,
		p.parallelism,
		encodedSalt,
		encodedHash,
	)

	return encodedEntry, nil
}

func ComparePasswordAndHash(password, encodedEntry string) (match bool, err error) {
	params, salt, hash, err := decodeEntry(encodedEntry)
	if err != nil {
		return false, err
	}

	calculatedHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		params.keyLength,
	)

	if bytes.Compare(hash, calculatedHash) == 0 {
		return true, nil
	}
	return false, nil
}

func generateRandomBytes(byteCount uint32) ([]byte, error) {
	randomBytes := make([]byte, byteCount)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	return randomBytes, nil
}

func decodeEntry(encodedEntry string) (params *HashingParams, salt, hash []byte, err error) {
	encodedEntryValues := strings.Split(encodedEntry, encodedEntryDelimiter)
	if len(encodedEntryValues) != 6 {
		return nil, nil, nil, ErrInvalidEncodedEntry
	}

	var hashingAlgorithm string
	_, err = fmt.Sscanf(encodedEntryValues[1], "%s", &hashingAlgorithm)
	if err != nil {
		return nil, nil, nil, err
	}
	if hashingAlgorithm != "argon2id" {
		return nil, nil, nil, ErrIncompatibleAlgorithm
	}

	var version int
	_, err = fmt.Sscanf(encodedEntryValues[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	params = &HashingParams{}
	_, err = fmt.Sscanf(
		encodedEntryValues[3],
		"m=%d,t=%d,p=%d",
		&params.memory,
		&params.iterations,
		&params.parallelism,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(encodedEntryValues[4])
	if err != nil {
		return nil, nil, nil, err
	}
	params.saltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(encodedEntryValues[5])
	if err != nil {
		return nil, nil, nil, err
	}
	params.keyLength = uint32(len(hash))

	return params, salt, hash, nil
}
