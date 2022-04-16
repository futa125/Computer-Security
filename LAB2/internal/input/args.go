package input

import (
	"flag"
	"fmt"

	"github.com/futa125/Computer-Security/LAB2/internal/hashing"
	"github.com/spf13/pflag"
)

type InvalidArgumentCountError struct {
	expectedCount int
	actualCount   int
}

func (e *InvalidArgumentCountError) Error() string {
	return fmt.Sprintf("invalid argument count, expected: %d, actual: %d", e.expectedCount, e.actualCount)
}

func ParseLoginArgs() (string, error) {
	flag.Parse()

	args := flag.Args()
	argCount := flag.NArg()
	if argCount != 1 {
		return "", &InvalidArgumentCountError{
			expectedCount: 1,
			actualCount:   argCount,
		}
	}

	user := args[0]

	return user, nil
}

func ParseUserManagementArgs() (string, string, error) {
	flag.Parse()

	args := flag.Args()
	argCount := flag.NArg()
	if argCount != 2 {
		return "", "", &InvalidArgumentCountError{
			expectedCount: 2,
			actualCount:   argCount,
		}
	}

	user, mode := args[0], args[1]

	return user, mode, nil
}

func ParseCrackerArgs() (
	params *hashing.Params,
	threadCount uint8,
	password,
	passwordsFilePath string,
) {
	params = &hashing.Params{}
	pflag.Uint32Var(&params.Memory, "argon-memory", hashing.DefaultHashingParams.Memory, "")
	pflag.Uint32Var(&params.Iterations, "argon-iterations", hashing.DefaultHashingParams.Iterations, "")
	pflag.Uint8Var(&params.Parallelism, "argon-parallelism", hashing.DefaultHashingParams.Parallelism, "")
	pflag.Uint32Var(&params.SaltLength, "argon-salt-length", hashing.DefaultHashingParams.SaltLength, "")
	pflag.Uint32Var(&params.KeyLength, "argon-key-length", hashing.DefaultHashingParams.KeyLength, "")

	pflag.Uint8Var(&threadCount, "threads", 1, "")

	pflag.StringVar(&password, "password", "", "")
	pflag.StringVar(&passwordsFilePath, "passwords-file", "", "")

	pflag.Parse()

	return params, threadCount, password, passwordsFilePath
}
