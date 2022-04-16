package main

import (
	"fmt"
	"log"

	"github.com/futa125/Computer-Security/LAB2/internal/hashing"
	"github.com/futa125/Computer-Security/LAB2/internal/input"
	"github.com/futa125/Computer-Security/LAB2/pkg/login"
)

const (
	dbFilePath      = "passwords.db"
	loginCountLimit = 3
)

func main() {
	user, err := input.ParseLoginArgs()
	if err != nil {
		log.Fatal(err)
	}

	loginCounter := 0

	for {
		err = login.Login(user, dbFilePath, hashing.DefaultHashingParams)
		loginCounter += 1

		switch err.(type) {
		case *input.PasswordMismatchError:
			fmt.Println(err)
			return
		case *input.PasswordTooWeakError:
			fmt.Println(err)
			return
		case *input.PasswordIdenticalError:
			fmt.Println(err)
			return
		case *login.InvalidCredentialsError:
			fmt.Println(err)
		case nil:
			fmt.Println("Login successful")
			return
		default:
			log.Fatal(err)
		}

		if loginCounter >= loginCountLimit {
			return
		}
	}
}
