package main

import (
	"fmt"
	"log"

	"github.com/futa125/Computer-Security/LAB2/internal/hashing"
	"github.com/futa125/Computer-Security/LAB2/internal/input"
	"github.com/futa125/Computer-Security/LAB2/pkg/login"
)

const dbFilePath = "passwords.db"

func main() {
	user, err := input.ParseLoginArgs()
	if err != nil {
		log.Fatal(err)
	}

	for {
		err = login.Login(user, dbFilePath, hashing.DefaultHashingParams)

		switch err {
		case login.ErrInvalidCredentials:
			fmt.Println("Username or password incorrect.")
		case nil:
			fmt.Println("Login successful.")
			return
		default:
			log.Fatal(err)
		}
	}
}
