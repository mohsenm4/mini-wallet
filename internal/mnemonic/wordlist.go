package mnemonic

import (
	_ "embed"
	"strings"
)

//go:embed english.txt
var englishRaw string

// Wordlist is the official BIP39 English wordlist (2048 words).
var Wordlist = strings.Split(strings.TrimSpace(englishRaw), "\n")
