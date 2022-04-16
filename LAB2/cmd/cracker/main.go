package main

import (
	"fmt"
	"log"

	"github.com/futa125/Computer-Security/LAB2/internal/hashing"
	"github.com/futa125/Computer-Security/LAB2/internal/input"
	"github.com/futa125/Computer-Security/LAB2/pkg/cracker"
)

func main() {
	params, threadCount, password, passwordsFilePath := input.ParseCrackerArgs()

	hash, err := hashing.GenerateHashFromPassword(password, params)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated hash: %s\n", hash)

	score := input.GetPasswordStrength(password, []string{})

	fmt.Printf("Password score: %d/%d", score, input.MaxPasswordScore)
	fmt.Println()

	c, err := cracker.CreateCracker(hash, passwordsFilePath, threadCount)
	if err != nil {
		log.Fatal(err)
	}

	c.CrackPassword()
}
