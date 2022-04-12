package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func main() {
	mode := *flag.String("mode", "", "")
	user := *flag.String("user", "", "")
	flag.Parse()

	switch mode {
	case "add":
		if user == "" {
			log.Fatal("User argument is empty")
		}

		CreateDatabaseManager
	}

}

func readPassword() (string, error) {
	fmt.Println("Password: ")
	bytePassword, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return "", err
	}

	password := string(bytePassword)

	return strings.TrimSpace(password), nil
}
