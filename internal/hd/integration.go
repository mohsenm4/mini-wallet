package hd

import "fmt"

func DerivePath(seed []byte, path string) (*PrivateKey, error) {
	indices, err := ParsePath(path)
	if err != nil {
		return nil, fmt.Errorf("parse path %q: %w", path, err)
	}

	key, err := NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}

	for depth, i := range indices {
		key, err = key.Child(i)
		if err != nil {
			return nil, fmt.Errorf("derive %s at depth %d (index %d): %w",
				FormatPath(indices[:depth+1]), depth, i, err)
		}
	}
	return key, nil
}
