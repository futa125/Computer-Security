package main

import (
	"fmt"
	"log"

	"github.com/futa125/Computer-Security/LAB2/internal/hashing"
	"github.com/futa125/Computer-Security/LAB2/internal/input"
	"github.com/futa125/Computer-Security/LAB2/pkg/usermanagment"
)

const dbFilePath = "passwords.db"

func main() {
	mode, user, err := input.ParseUserManagementArgs()
	if err != nil {
		log.Fatal(err)
	}

	switch mode {
	case "add":
		err := usermanagment.AddUser(user, dbFilePath, hashing.DefaultHashingParams)
		switch err {
		case input.ErrPasswordMismatch:
			fmt.Println("User add failed. Password mismatch.")
		case usermanagment.ErrUserExists:
			fmt.Println("User add failed. User already exists")
		case nil:
			fmt.Printf("User %s successfuly added.\n", user)
		default:
			log.Fatal(err)
		}
	case "passwd":
		err := usermanagment.ChangePassword(user, dbFilePath, hashing.DefaultHashingParams)
		switch err {
		case input.ErrPasswordMismatch:
			fmt.Println("Password change failed. Password mismatch.")
		case usermanagment.ErrUserNotFound:
			fmt.Println("Password change failed. User doesn't exists")
		case nil:
			fmt.Println("Password change successful.")
		default:
			log.Fatal(err)
		}
	case "forcepass":
		err := usermanagment.ForcePasswordReset(user, dbFilePath)
		switch err {
		case usermanagment.ErrUserNotFound:
			fmt.Println("Force password change failed. User doesn't exists")
		case nil:
			fmt.Println("User will be requested to change password on next login.")
		default:
			log.Fatal(err)
		}
	case "del":
		err := usermanagment.DeleteUser(user, dbFilePath)
		switch err {
		case usermanagment.ErrUserNotFound:
			fmt.Println("Delete user failed. User doesn't exists")
		case nil:
			fmt.Println("User successfully removed.")
		default:
			log.Fatal(err)
		}
	}

}
