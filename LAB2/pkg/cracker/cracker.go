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
	wordList    []string
	hash        string
	threadCount uint8
}

func CreateCracker(hash, wordListFilePath string, threadCount uint8) (*cracker, error) {
	wordList, err := readWordListFile(wordListFilePath)
	if err != nil {
		return nil, err
	}

	return &cracker{
		wordList:    wordList,
		hash:        hash,
		threadCount: threadCount,
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
		go checkPasswordMatch(ctx, cancel, &wg, wordChan, c.hash)
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
	hash string,
) {
	defer wg.Done()

	for {
		select {
		case word := <-wordChan:
			success, _, _ := hashing.ComparePasswordAndHash(word, hash)
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
