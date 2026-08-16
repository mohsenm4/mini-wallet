package mnemonic

import "testing"

func TestWordlistLength(t *testing.T) {
	if got, want := len(Wordlist), 2048; got != want {
		t.Errorf("Wordlist length = %d, want %d", got, want)
	}
}

func TestWordlistFirstAndLast(t *testing.T) {
	if got, want := Wordlist[0], "abandon"; got != want {
		t.Errorf("Wordlist[0] = %q, want %q", got, want)
	}
	if got, want := Wordlist[2047], "zoo"; got != want {
		t.Errorf("Wordlist[2047] = %q, want %q", got, want)
	}
}
