package usermanagment

import (
	"errors"

	"github.com/futa125/Computer-Security/LAB2/internal/database"
	"github.com/futa125/Computer-Security/LAB2/internal/hashing"
	"github.com/futa125/Computer-Security/LAB2/internal/input"
)

var (
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")
)

func AddUser(user, dbFilePath string, params *hashing.Params) error {
	hashedUser := hashing.CalculateSha256(user)

	client, dbCloseFunc, err := database.CreateDatabaseClient(dbFilePath)
	if err != nil {
		return err
	}
	defer dbCloseFunc()

	databaseEntry, err := client.GetDatabaseEntry(hashedUser)
	if err != nil {
		return err
	}
	if databaseEntry != (database.Entry{}) {
		return ErrUserExists
	}

	password, err := input.ReadPassword("Password", true)
	if err != nil {
		return err
	}

	hashedPassword, err := hashing.GenerateHashFromPassword(password, params)
	if err != nil {
		return err
	}

	databaseEntry = database.Entry{
		HashedUser:     hashedUser,
		HashedPassword: hashedPassword,
		ResetPassword:  false,
	}

	err = client.SaveDatabaseEntry(databaseEntry)
	if err != nil {
		return err
	}

	return nil
}

func ChangePassword(user, dbFilePath string, params *hashing.Params) error {
	hashedUser := hashing.CalculateSha256(user)

	client, dbCloseFunc, err := database.CreateDatabaseClient(dbFilePath)
	if err != nil {
		return err
	}
	defer dbCloseFunc()

	databaseEntry, err := client.GetDatabaseEntry(hashedUser)
	if err != nil {
		return err
	}
	if databaseEntry == (database.Entry{}) {
		return ErrUserNotFound
	}

	password, err := input.ReadPassword("Password", true)
	if err != nil {
		return err
	}

	hashedPassword, err := hashing.GenerateHashFromPassword(password, params)
	if err != nil {
		return err
	}

	databaseEntry.HashedPassword = hashedPassword

	err = client.SaveDatabaseEntry(databaseEntry)
	if err != nil {
		return err
	}

	return nil
}

func ForcePasswordReset(user, dbFilePath string) error {
	user = hashing.CalculateSha256(user)

	client, dbCloseFunc, err := database.CreateDatabaseClient(dbFilePath)
	if err != nil {
		return err
	}
	defer dbCloseFunc()

	databaseEntry, err := client.GetDatabaseEntry(user)
	if err != nil {
		return err
	}
	if databaseEntry == (database.Entry{}) {
		return ErrUserNotFound
	}

	databaseEntry.ResetPassword = true

	err = client.SaveDatabaseEntry(databaseEntry)
	if err != nil {
		return err
	}

	return nil
}

func DeleteUser(user, dbFilePath string) error {
	user = hashing.CalculateSha256(user)

	client, dbCloseFunc, err := database.CreateDatabaseClient(dbFilePath)
	if err != nil {
		return err
	}
	defer dbCloseFunc()

	databaseEntry, err := client.GetDatabaseEntry(user)
	if err != nil {
		return err
	}
	if databaseEntry == (database.Entry{}) {
		return ErrUserNotFound
	}

	err = client.RemoveDatabaseEntry(databaseEntry)
	if err != nil {
		return err
	}

	return nil
}
