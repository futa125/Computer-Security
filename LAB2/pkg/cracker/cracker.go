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
	wordList     []string
	argon2idHash string
	threadCount  uint
}

func CreateCracker(argon2idHash, wordListFilePath string, threadCount uint) (*cracker, error) {
	wordList, err := readWordListFile(wordListFilePath)
	if err != nil {
		return nil, err
	}

	return &cracker{
		wordList:     wordList,
		argon2idHash: argon2idHash,
		threadCount:  threadCount,
	}, nil
}

func (c *cracker) CrackPassword() {
	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}

	wordChan := make(chan string, len(c.wordList))
	for _, word := range c.wordList {
		wordChan <- word
	}

	for i := 0; i < int(c.threadCount); i++ {
		wg.Add(1)
		go checkPasswordMatch(ctx, cancel, &wg, wordChan, c.argon2idHash)
	}

	wg.Wait()

	cancel()
}

func readWordListFile(wordListFilePath string) (wordList []string, err error) {
	wordListFile, err := os.Open(wordListFilePath)
	if err != nil {
		return nil, err
	}

	defer func(wordListFile *os.File) {
		closeErr := wordListFile.Close()
		if closeErr != nil {
			err = closeErr
		}
	}(wordListFile)

	scanner := bufio.NewScanner(wordListFile)
	for scanner.Scan() {
		wordList = append(wordList, scanner.Text())
	}

	if err = scanner.Err(); err != nil {
		return nil, err
	}

	return wordList, err
}

func checkPasswordMatch(
	ctx context.Context,
	cancelFunc context.CancelFunc,
	wg *sync.WaitGroup,
	wordChan <-chan string,
	argon2idHash string,
) {
	defer wg.Done()

	for {
		select {
		case word := <-wordChan:
			success, _, _ := hashing.ComparePasswordAndHash(word, argon2idHash)
			if success {
				fmt.Printf("Match found, checked word: %s\n", word)
				cancelFunc()
			} else {
				fmt.Printf("Match not found, checked word: %s\n", word)
			}
		case <-ctx.Done():
			return
		}
	}
}
