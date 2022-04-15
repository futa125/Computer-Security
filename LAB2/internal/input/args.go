package input

import (
	"errors"
	"flag"
)

var ErrInvalidArgument = errors.New("invalid argument")

func ParseLoginArgs() (string, error) {
	flag.Parse()

	args := flag.Args()
	if flag.NArg() != 1 {
		return "", ErrInvalidArgument
	}

	user := args[0]
	if user == "" {
		return "", ErrInvalidArgument
	}

	return user, nil
}

func ParseUserManagementArgs() (string, string, error) {
	flag.Parse()

	args := flag.Args()
	if flag.NArg() != 2 {
		return "", "", ErrInvalidArgument
	}

	user, mode := args[0], args[1]
	if user == "" || mode == "" {
		return "", "", ErrInvalidArgument
	}

	return user, mode, nil
}

func ParseCrackerArgs() (argon2idHash, wordListFilePath string, threadCount uint) {
	flag.StringVar(&argon2idHash, "hash", "", "")
	flag.StringVar(&wordListFilePath, "wordlist", "", "")
	flag.UintVar(&threadCount, "threads", 2, "")
	flag.Parse()

	return argon2idHash, wordListFilePath, threadCount
}
