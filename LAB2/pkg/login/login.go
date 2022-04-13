package login

import (
	"errors"

	"github.com/futa125/Computer-Security/LAB2/internal/database"
	"github.com/futa125/Computer-Security/LAB2/internal/hashing"
	"github.com/futa125/Computer-Security/LAB2/internal/input"
)

var ErrInvalidCredentials = errors.New("invalid username or password")

func Login(user, dbFilePath string, params *hashing.Params) error {
	hashedUser := hashing.CalculateSha256(user)

	password, err := input.ReadPassword("Password", false)
	if err != nil {
		return err
	}

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
		return ErrInvalidCredentials
	}

	match, err := hashing.ComparePasswordAndHash(password, databaseEntry.HashedPassword)
	if err != nil {
		return err
	}
	if !match {
		return ErrInvalidCredentials
	}

	if databaseEntry.ResetPassword {
		err := resetPassword(hashedUser, client, params)
		if err != nil {
			return err
		}
	}

	return nil
}

func resetPassword(hashedUser string, client database.Client, params *hashing.Params) error {
	password, err := input.ReadPassword("New password", true)
	hashedPassword, err := hashing.GenerateHashFromPassword(password, params)
	if err != nil {
		return err
	}

	databaseEntry := database.Entry{
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
