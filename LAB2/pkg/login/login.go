package login

import (
	"fmt"

	"github.com/futa125/Computer-Security/LAB2/internal/database"
	"github.com/futa125/Computer-Security/LAB2/internal/hashing"
	"github.com/futa125/Computer-Security/LAB2/internal/input"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/argon2"
)

var fakeEntry = database.Entry{
	HashedPassword: fmt.Sprintf(
		hashing.EntryFormatting,
		hashing.Algorithm,
		argon2.Version,
		hashing.DefaultHashingParams.Memory,
		hashing.DefaultHashingParams.Iterations,
		hashing.DefaultHashingParams.Parallelism,
		"foo",
		"foo",
	),
}

type InvalidCredentialsError struct{}

func (e *InvalidCredentialsError) Error() string {
	return "Invalid username or password"
}

func Login(user, dbFilePath string, params *hashing.Params) error {
	password, err := input.ReadPassword()
	if err != nil {
		return err
	}

	client, err := database.CreateDatabaseClient(dbFilePath)
	if err != nil {
		return err
	}

	databaseEntry, err := client.GetDatabaseEntry(user)
	if err != nil {
		return err
	}

	if databaseEntry == (database.Entry{}) {
		databaseEntry = fakeEntry
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
	hashedPassword, err := hashing.GenerateHashFromPassword(password, params)
	if err != nil {
		return err
	}

	databaseEntry := database.Entry{
		Username:       user,
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
	password, err := input.ReadNewPassword()
	if err != nil {
		return err
	}

	databaseEntry, err := client.GetDatabaseEntry(user)
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
		Username:       user,
		HashedPassword: hashedPassword,
		ResetPassword:  false,
	}

	err = client.SaveDatabaseEntry(databaseEntry)
	if err != nil {
		return err
	}

	return nil
}
