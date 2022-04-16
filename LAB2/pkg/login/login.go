package login

import (
	"github.com/futa125/Computer-Security/LAB2/internal/database"
	"github.com/futa125/Computer-Security/LAB2/internal/hashing"
	"github.com/futa125/Computer-Security/LAB2/internal/input"
	"github.com/google/go-cmp/cmp"
)

type InvalidCredentialsError struct{}

func (e *InvalidCredentialsError) Error() string {
	return "Invalid username or password"
}

func Login(user, dbFilePath string, params *hashing.Params) error {
	hashedUser := hashing.CalculateSha256(user)

	password, err := input.ReadPassword()
	if err != nil {
		return err
	}

	client, err := database.CreateDatabaseClient(dbFilePath)
	if err != nil {
		return err
	}

	databaseEntry, err := client.GetDatabaseEntry(hashedUser)
	if err != nil {
		return err
	}

	if databaseEntry == (database.Entry{}) {
		return &InvalidCredentialsError{}
	}

	match, usedParams, err := hashing.ComparePasswordAndHash(password, databaseEntry.HashedPassword)
	if err != nil {
		return err
	}
	if !match {
		return &InvalidCredentialsError{}
	}

	if !cmp.Equal(params, usedParams) && !databaseEntry.ResetPassword {
		err := rehashPassword(user, password, client, params)
		if err != nil {
			return err
		}
	} else if databaseEntry.ResetPassword {
		err := resetPassword(user, client, params)
		if err != nil {
			return err
		}
	}

	return nil
}

func rehashPassword(user, password string, client database.Client, params *hashing.Params) error {
	hashedUser := hashing.CalculateSha256(user)
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

func resetPassword(user string, client database.Client, params *hashing.Params) error {
	hashedUser := hashing.CalculateSha256(user)
	password, err := input.ReadNewPassword()
	if err != nil {
		return err
	}

	databaseEntry, err := client.GetDatabaseEntry(hashedUser)
	if err != nil {
		return err
	}

	err = input.CheckPasswordIdentical(password, databaseEntry.HashedPassword)
	if err != nil {
		return err
	}

	err = input.CheckPasswordStrength(password, []string{user})
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
