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
