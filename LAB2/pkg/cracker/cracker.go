package cracker

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/futa125/Computer-Security/LAB2/internal/hashing"
)

type cracker struct {
	passwords   []string
	hash        string
	threadCount uint8
}

func CreateCracker(hash, passwordsFilePath string, threadCount uint8) (*cracker, error) {
	passwords, err := readPasswordsFile(passwordsFilePath)
	if err != nil {
		return nil, err
	}

	return &cracker{
		passwords:   passwords,
		hash:        hash,
		threadCount: threadCount,
	}, nil
}

func (c *cracker) CrackPassword() {
	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}

	passwordsChan := make(chan string, len(c.passwords))
	for _, password := range c.passwords {
		passwordsChan <- password
	}

	for i := 0; i < int(c.threadCount); i++ {
		wg.Add(1)
		go c.checkPasswordMatch(ctx, cancel, &wg, passwordsChan)
	}

	wg.Wait()

	cancel()
}

func readPasswordsFile(passwordsFilePath string) (passwords []string, err error) {
	passwordsFile, err := os.Open(passwordsFilePath)
	if err != nil {
		return nil, err
	}

	defer func(wordListFile *os.File) {
		closeErr := wordListFile.Close()
		if closeErr != nil {
			err = closeErr
		}
	}(passwordsFile)

	scanner := bufio.NewScanner(passwordsFile)
	for scanner.Scan() {
		passwords = append(passwords, scanner.Text())
	}

	if err = scanner.Err(); err != nil {
		return nil, err
	}

	return passwords, err
}

func (c *cracker) checkPasswordMatch(
	ctx context.Context,
	cancelFunc context.CancelFunc,
	wg *sync.WaitGroup,
	passwordsChan <-chan string,
) {
	defer wg.Done()

	for {
		select {
		case password := <-passwordsChan:
			success, _, _ := hashing.ComparePasswordAndHash(password, c.hash)
			if success {
				fmt.Printf("Match found, checked password: %s\n", password)
				cancelFunc()
			} else {
				fmt.Printf("Match not found, checked password: %s\n", password)
			}
		case <-ctx.Done():
			return
		}
	}
}
