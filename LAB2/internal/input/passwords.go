package input

import (
	"bytes"
	"fmt"
	"strings"
	"syscall"

	"github.com/futa125/Computer-Security/LAB2/internal/hashing"
	"github.com/trustelem/zxcvbn"
	"golang.org/x/term"
)

const (
	MinValidPasswordScore = 3
	MaxPasswordScore      = 4
)

type PasswordMismatchError struct{}

type PasswordTooWeakError struct {
	expectedScore int
	actualScore   int
}

type PasswordIdenticalError struct{}

func (e *PasswordMismatchError) Error() string {
	return "Password mismatch"
}

func (e *PasswordTooWeakError) Error() string {
	return fmt.Sprintf("Password too weak, score should be >= %d, actual score: %d", e.expectedScore, e.actualScore)
}

func (e *PasswordIdenticalError) Error() string {
	return "New password can't be same as old password"
}

func ReadPassword() (string, error) {
	fmt.Printf("Password: ")
	bytePassword, err := term.ReadPassword(syscall.Stdin)
	fmt.Println()
	if err != nil {
		return "", err
	}

	password := strings.TrimSpace(string(bytePassword))

	return password, nil
}

func ReadPasswordWithRepeat() (string, error) {
	fmt.Printf("Password: ")
	bytePassword, err := term.ReadPassword(syscall.Stdin)
	fmt.Println()
	if err != nil {
		return "", err
	}

	fmt.Printf("Repeat password: ")
	bytePasswordRepeated, err := term.ReadPassword(syscall.Stdin)
	fmt.Println()
	if err != nil {
		return "", err
	}

	if bytes.Compare(bytePassword, bytePasswordRepeated) != 0 {
		return "", &PasswordMismatchError{}
	}

	password := strings.TrimSpace(string(bytePassword))

	return password, nil
}

func ReadNewPassword() (string, error) {
	fmt.Printf("New password: ")
	bytePassword, err := term.ReadPassword(syscall.Stdin)
	fmt.Println()
	if err != nil {
		return "", err
	}

	fmt.Printf("Repeat new password: ")
	bytePasswordRepeated, err := term.ReadPassword(syscall.Stdin)
	fmt.Println()
	if err != nil {
		return "", err
	}

	if bytes.Compare(bytePassword, bytePasswordRepeated) != 0 {
		return "", &PasswordMismatchError{}
	}

	password := strings.TrimSpace(string(bytePassword))

	return password, nil
}

func CheckPasswordStrength(password string, keywords []string) error {
	if score := GetPasswordStrength(password, keywords); score < MinValidPasswordScore {
		return &PasswordTooWeakError{
			expectedScore: MinValidPasswordScore,
			actualScore:   score,
		}
	}

	return nil
}

func GetPasswordStrength(password string, keywords []string) int {
	result := zxcvbn.PasswordStrength(password, keywords)

	return result.Score
}

func CheckPasswordIdentical(password, hashedPassword string) error {
	identical, _, err := hashing.ComparePasswordAndHash(password, hashedPassword)
	if err != nil {
		return err
	}

	if identical {
		return &PasswordIdenticalError{}
	}

	return nil
}
