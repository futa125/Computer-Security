package usermanagment

import (
	"fmt"

	"github.com/futa125/Computer-Security/LAB2/internal/database"
	"github.com/futa125/Computer-Security/LAB2/internal/hashing"
	"github.com/futa125/Computer-Security/LAB2/internal/input"
)

type UserExistsError struct {
	user string
}

type UserNotFoundError struct {
	user string
}

func (e *UserExistsError) Error() string {
	return fmt.Sprintf("User already exists: %s", e.user)
}

func (e *UserNotFoundError) Error() string {
	return fmt.Sprintf("User not found: %s", e.user)
}

func AddUser(user, dbFilePath string, params *hashing.Params) error {
	client, err := database.CreateDatabaseClient(dbFilePath)
	if err != nil {
		return err
	}

	databaseEntry, err := client.GetDatabaseEntry(user)
	if err != nil {
		return err
	}
	if databaseEntry != (database.Entry{}) {
		return &UserExistsError{
			user: user,
		}
	}

	password, err := input.ReadPasswordWithRepeat()
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
		User:           user,
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
	client, err := database.CreateDatabaseClient(dbFilePath)
	if err != nil {
		return err
	}

	databaseEntry, err := client.GetDatabaseEntry(user)
	if err != nil {
		return err
	}
	if databaseEntry == (database.Entry{}) {
		return &UserNotFoundError{
			user: user,
		}
	}

	password, err := input.ReadPasswordWithRepeat()
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

	databaseEntry.HashedPassword = hashedPassword

	err = client.SaveDatabaseEntry(databaseEntry)
	if err != nil {
		return err
	}

	return nil
}

func ForcePasswordReset(user, dbFilePath string) error {
	client, err := database.CreateDatabaseClient(dbFilePath)
	if err != nil {
		return err
	}

	databaseEntry, err := client.GetDatabaseEntry(user)
	if err != nil {
		return err
	}
	if databaseEntry == (database.Entry{}) {
		return &UserNotFoundError{
			user: user,
		}
	}

	databaseEntry.ResetPassword = true

	err = client.SaveDatabaseEntry(databaseEntry)
	if err != nil {
		return err
	}

	return nil
}

func DeleteUser(user, dbFilePath string) error {
	client, err := database.CreateDatabaseClient(dbFilePath)
	if err != nil {
		return err
	}

	databaseEntry, err := client.GetDatabaseEntry(user)
	if err != nil {
		return err
	}
	if databaseEntry == (database.Entry{}) {
		return &UserNotFoundError{
			user: user,
		}
	}

	err = client.RemoveDatabaseEntry(databaseEntry)
	if err != nil {
		return err
	}

	return nil
}
