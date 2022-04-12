package main

import (
	"errors"
	"flag"
	"log"

	"github.com/futa125/Computer-Security/LAB2/internal/database"
	"github.com/futa125/Computer-Security/LAB2/internal/hashing"
)

const filePath = "passwords.db"

func main() {
	flag.Parse()
	args := flag.Args()
	user := args[0]
	params := hashing.CreateHashingParams(64*1024, 6, 16, 32, 2)
	err := login(user, params)
	if err != nil {
		log.Fatal(err)
	}
}

func login(user string, params hashing.Params) error {
	if user == "" {
		return errors.New("user argument is empty")
	}

	password, err := hashing.ReadPassword(false)
	if err != nil {
		return err
	}

	manager, dbCloseFunc, err := database.CreateDatabaseManager(filePath)
	if err != nil {
		return err
	}
	defer dbCloseFunc()

	databaseEntry, err := manager.GetDatabaseEntry(user)
	if err != nil {
		return err
	}

	match, err := hashing.ComparePasswordAndHash(password, databaseEntry.HashedPassword)
	if err != nil {
		return err
	}
	if !match {
		return errors.New("invalid username or password")
	}

	if databaseEntry.ResetPassword {
		password, err = hashing.ReadPassword(true)
		encodedEntry, err := hashing.GenerateHashFromPassword(password, &params)
		if err != nil {
			return err
		}

		databaseEntry.HashedPassword = encodedEntry
		databaseEntry.ResetPassword = false

		err = manager.SaveDatabaseEntry(databaseEntry)
		if err != nil {
			return err
		}
	}

	return nil
}
