package input

import (
	"flag"
	"fmt"

	"github.com/futa125/Computer-Security/LAB2/internal/hashing"
	"github.com/spf13/pflag"
)

type InvalidArgumentError struct {
	argument string
	value    string
}

func (e *InvalidArgumentError) Error() string {
	return fmt.Sprintf("invalid argument '%s' with value '%s'", e.argument, e.value)
}

func ParseLoginArgs() (string, error) {
	flag.Parse()

	args := flag.Args()
	if flag.NArg() != 1 {
		return "", &InvalidArgumentError{
			argument: "login",
			value:    "",
		}
	}

	user := args[0]
	if user == "" {
		return "", &InvalidArgumentError{
			argument: "user",
			value:    "",
		}
	}

	return user, nil
}

func ParseUserManagementArgs() (string, string, error) {
	flag.Parse()

	args := flag.Args()
	if flag.NArg() != 2 {
		return "", "", &InvalidArgumentError{
			argument: "mode,user",
			value:    "",
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
