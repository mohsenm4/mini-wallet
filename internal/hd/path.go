package hd

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ParsePath parses a BIP32 derivation path like "m/44'/60'/0'/0/5" into
// a slice of uint32 indices. Segments ending in "'" are hardened and
// get HardenedOffset (0x80000000) added.
//
// "m" alone returns an empty slice (master key, no derivation).
func ParsePath(s string) ([]uint32, error) {
	if s == "" {
		return nil, errors.New("empty path")
	}
	parts := strings.Split(s, "/")
	if parts[0] != "m" {
		return nil, errors.New(`path must start with "m"`)
	}
	parts = parts[1:]

	result := make([]uint32, 0, len(parts))
	for _, seg := range parts {
		if seg == "" {
			return nil, errors.New("empty path segment")
		}

		hardened := strings.HasSuffix(seg, "'")
		if hardened {
			seg = seg[:len(seg)-1]
		}

		n, err := strconv.ParseUint(seg, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid path segment %q: %w", seg, err)
		}
		index := uint32(n)

		if !hardened && index >= HardenedOffset {
			return nil, fmt.Errorf("non-hardened index %d exceeds 2^31", index)
		}

		if hardened {
			index += HardenedOffset
		}
		result = append(result, index)
	}
	return result, nil
}

// FormatPath is the inverse of ParsePath. Given a slice of uint32
// indices, it produces the canonical string form "m/44'/60'/0'/0/5".
// Indices >= HardenedOffset are rendered as N' where N = index - HardenedOffset.
func FormatPath(path []uint32) string {
	if len(path) == 0 {
		return "m"
	}
	parts := make([]string, len(path))
	for i, index := range path {
		if index >= HardenedOffset {
			parts[i] = strconv.FormatUint(uint64(index-HardenedOffset), 10) + "'"
		} else {
			parts[i] = strconv.FormatUint(uint64(index), 10)
		}
	}
	return "m/" + strings.Join(parts, "/")
}
