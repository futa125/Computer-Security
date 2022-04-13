package input

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unicode"

	"golang.org/x/term"
)

var ErrPasswordMismatch = errors.New("password mismatch")

func ReadPassword(promptText string, recheck bool) (string, error) {
	regularPrompt := capitalizeFirstWord(fmt.Sprintf("%s: ", promptText))
	repeatPrompt := capitalizeFirstWord(fmt.Sprintf("Repeat %s: ", promptText))

	fmt.Printf(regularPrompt)
	bytePassword, err := term.ReadPassword(syscall.Stdin)
	fmt.Println()
	if err != nil {
		return "", err
	}

	if recheck {
		fmt.Printf(repeatPrompt)
		repeatedBytePassword, err := term.ReadPassword(syscall.Stdin)
		fmt.Println()
		if err != nil {
			return "", err
		}

		if bytes.Compare(bytePassword, repeatedBytePassword) != 0 {
			return "", ErrPasswordMismatch
		}
	}

	password := string(bytePassword)

	return strings.TrimSpace(password), nil
}

func capitalizeFirstWord(text string) string {
	r := []rune(strings.ToLower(text))
	return string(append([]rune{unicode.ToUpper(r[0])}, r[1:]...))
}
