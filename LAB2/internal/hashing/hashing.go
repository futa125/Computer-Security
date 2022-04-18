package hashing

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	Algorithm       = "argon2id"
	EntryFormatting = "$%s$v=%d$m=%d,t=%d,p=%d$%s$%s"
)

type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

type InvalidEntryFormattingError struct {
	expectedFormatting string
	input              string
}

type IncompatibleAlgorithmError struct {
	expectedAlgorithm string
	actualAlgorithm   string
}

type IncompatibleVersionError struct {
	expectedVersion int
	actualVersion   int
}

func (e *InvalidEntryFormattingError) Error() string {
	return "The encoded entry is not in the correct format"
}

func (e *IncompatibleAlgorithmError) Error() string {
	return "Algorithm should be argon2id"
}

func (e *IncompatibleVersionError) Error() string {
	return "Incompatible version of argon2id"
}

var DefaultHashingParams = &Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

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
		EntryFormatting,
		Algorithm,
		argon2.Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		encodedSalt,
		encodedHash,
	)

	return entry, nil
}

func ComparePasswordAndHash(password, entry string) (bool, *Params, error) {
	params, salt, hash, err := decodeEntry(entry)
	if err != nil {
		return false, params, err
	}

	calculatedHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	if subtle.ConstantTimeCompare(hash, calculatedHash) == 0 {
		return false, params, nil
	}

	return true, params, nil
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
		return nil, nil, nil, &InvalidEntryFormattingError{
			expectedFormatting: EntryFormatting,
			input:              entry,
		}
	}

	var usedAlgorithm string
	_, err = fmt.Sscanf(entryValues[1], "%s", &usedAlgorithm)
	if err != nil {
		return nil, nil, nil, err
	}

	if usedAlgorithm != Algorithm {
		return nil, nil, nil, &IncompatibleAlgorithmError{
			actualAlgorithm:   usedAlgorithm,
			expectedAlgorithm: Algorithm,
		}
	}

	var version int
	_, err = fmt.Sscanf(entryValues[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, &IncompatibleVersionError{
			expectedVersion: argon2.Version,
			actualVersion:   version,
		}
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
