package main

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

func readPassword() (string, error) {
	password := os.Getenv("WALLET_PASSWORD")
	if password != "" {
		return password, nil
	}

	fmt.Fprint(os.Stderr, "Enter password: ")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(passBytes), nil
}
