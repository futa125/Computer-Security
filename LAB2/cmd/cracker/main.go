package main

import (
	"log"

	"github.com/futa125/Computer-Security/LAB2/internal/input"
	"github.com/futa125/Computer-Security/LAB2/pkg/cracker"
)

func main() {
	argon2idHash, wordListFilePath, threadCount := input.ParseCrackerArgs()
	c, err := cracker.CreateCracker(argon2idHash, wordListFilePath, threadCount)
	if err != nil {
		log.Fatal(err)
	}

	c.CrackPassword()
}
