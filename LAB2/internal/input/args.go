package input

import (
	"errors"
	"flag"

	"github.com/futa125/Computer-Security/LAB2/internal/hashing"
	"github.com/spf13/pflag"
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

func ParseCrackerArgs() (
	params *hashing.Params,
	threadCount uint8,
	password,
	passwordsFilePath string,
) {
	params = &hashing.Params{}
	pflag.Uint32Var(&params.Memory, "argon-memory", 128, "")
	pflag.Uint32Var(&params.Iterations, "argon-iterations", 4, "")
	pflag.Uint8Var(&params.Parallelism, "argon-parallelism", 4, "")
	pflag.Uint32Var(&params.SaltLength, "argon-salt-length", 16, "")
	pflag.Uint32Var(&params.KeyLength, "argon-key-length", 32, "")

	pflag.Uint8Var(&threadCount, "threads", 4, "")

	pflag.StringVar(&password, "password", "", "")
	pflag.StringVar(&passwordsFilePath, "passwords-file", "", "")

	pflag.Parse()

	params.Memory = params.Memory * 1024

	return params, threadCount, password, passwordsFilePath
}
