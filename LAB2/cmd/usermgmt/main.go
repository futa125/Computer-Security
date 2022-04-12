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
	mode, user := args[0], args[1]
	params := hashing.CreateHashingParams(64*1024, 6, 16, 32, 2)

	switch mode {
	case "add":
		err := addUser(user, params)
		if err != nil {
			log.Fatal(err)
		}
	case "passwd":
		err := changePassword(user, params)
		if err != nil {
			log.Fatal(err)
		}
	case "forcepass":
		err := forcePasswordReset(user)
		if err != nil {
			log.Fatal(err)
		}
	case "del":
		err := deleteUser(user)
		if err != nil {
			log.Fatal(err)
		}
	}

}

func addUser(user string, params hashing.Params) error {
	if user == "" {
		return errors.New("user argument is empty")
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
	if databaseEntry != (database.Entry{}) {
		return errors.New("user already exists")
	}

	password, err := hashing.ReadPassword(true)
	if err != nil {
		return err
	}

	hashedPassword, err := hashing.GenerateHashFromPassword(password, &params)
	if err != nil {
		return err
	}

	dbEntry := database.CreateDatabaseEntry(user, hashedPassword, false)

	err = manager.SaveDatabaseEntry(dbEntry)
	if err != nil {
		return err
	}

	return nil
}

func changePassword(user string, params hashing.Params) error {
	if user == "" {
		return errors.New("user argument is empty")
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
	if databaseEntry == (database.Entry{}) {
		return errors.New("user not found")
	}

	password, err := hashing.ReadPassword(true)
	if err != nil {
		return err
	}

	hashedPassword, err := hashing.GenerateHashFromPassword(password, &params)
	if err != nil {
		return err
	}

	dbEntry := database.CreateDatabaseEntry(user, hashedPassword, false)

	err = manager.SaveDatabaseEntry(dbEntry)
	if err != nil {
		return err
	}

	return nil
}

func forcePasswordReset(user string) error {
	if user == "" {
		return errors.New("user argument is empty")
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
	if databaseEntry == (database.Entry{}) {
		return errors.New("user not found")
	}

	databaseEntry.ResetPassword = true

	err = manager.SaveDatabaseEntry(databaseEntry)
	if err != nil {
		return err
	}

	return nil
}

func deleteUser(user string) error {
	if user == "" {
		return errors.New("user argument is empty")
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
	if databaseEntry == (database.Entry{}) {
		return errors.New("user not found")
	}

	err = manager.RemoveDatabaseEntry(databaseEntry)
	if err != nil {
		return err
	}

	return nil
}
