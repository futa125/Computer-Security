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

		switch err.(type) {
		case *input.PasswordMismatchError:
			fmt.Println(err)
		case *input.PasswordTooWeakError:
			fmt.Println(err)
		case *usermanagment.UserExistsError:
			fmt.Println(err)
		case nil:
			fmt.Println("Username successfully added")
		default:
			log.Fatal(err)
		}
	case "passwd":
		err := usermanagment.ChangePassword(user, dbFilePath, hashing.DefaultHashingParams)

		switch err.(type) {
		case *input.PasswordMismatchError:
			fmt.Println(err)
		case *input.PasswordTooWeakError:
			fmt.Println(err)
		case *input.PasswordIdenticalError:
			fmt.Println(err)
		case *usermanagment.UserNotFoundError:
			fmt.Println(err)
		case nil:
			fmt.Println("Password change successful")
		default:
			log.Fatal(err)
		}
	case "forcepass":
		err := usermanagment.ForcePasswordReset(user, dbFilePath)

		switch err.(type) {
		case *usermanagment.UserNotFoundError:
			fmt.Println(err)
		case nil:
			fmt.Println("Username will be requested to change password on next login")
		default:
			log.Fatal(err)
		}
	case "del":
		err := usermanagment.DeleteUser(user, dbFilePath)

		switch err.(type) {
		case *usermanagment.UserNotFoundError:
			fmt.Println(err)
		case nil:
			fmt.Println("Username successfully removed")
		default:
			log.Fatal(err)
		}
	default:
		log.Fatalf("Invalid mode argument: %s", mode)
	}

}
