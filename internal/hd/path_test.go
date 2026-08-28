package hd

import (
	"slices"
	"testing"
)

func TestParsePath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []uint32
		wantErr bool
	}{
		{
			name:  "BIP44 Ethereum",
			input: "m/44'/60'/0'/0/5",
			want:  []uint32{HardenedOffset + 44, HardenedOffset + 60, HardenedOffset, 0, 5},
		},
		{
			name:  "master only",
			input: "m",
			want:  []uint32{},
		},
		{
			name:  "single non-hardened",
			input: "m/0",
			want:  []uint32{0},
		},
		{
			name:  "single hardened",
			input: "m/0'",
			want:  []uint32{HardenedOffset},
		},
		{
			name:  "all non-hardened",
			input: "m/44/60/0/0/5",
			want:  []uint32{44, 60, 0, 0, 5},
		},
		{
			name:  "large non-hardened index just under 2^31",
			input: "m/2147483647",
			want:  []uint32{HardenedOffset - 1},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "missing m prefix",
			input:   "44'/60'",
			wantErr: true,
		},
		{
			name:    "non-numeric segment",
			input:   "m/44'/abc",
			wantErr: true,
		},
		{
			name:    "non-hardened index equal to 2^31",
			input:   "m/2147483648",
			wantErr: true,
		},
		{
			name:    "overflow uint32",
			input:   "m/5000000000",
			wantErr: true,
		},
		{
			name:    "negative segment",
			input:   "m/-1",
			wantErr: true,
		},
		{
			name:    "empty segment (trailing slash)",
			input:   "m/44'/",
			wantErr: true,
		},
		{
			name:    "lone quote segment",
			input:   "m/'",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePath(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParsePath(%q) expected error, got nil (result: %v)", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePath(%q) unexpected error: %v", tt.input, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("ParsePath(%q) = %v; want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatPath(t *testing.T) {
	tests := []struct {
		name  string
		input []uint32
		want  string
	}{
		{
			name:  "empty means master",
			input: []uint32{},
			want:  "m",
		},
		{
			name:  "nil means master",
			input: nil,
			want:  "m",
		},
		{
			name:  "BIP44 Ethereum",
			input: []uint32{HardenedOffset + 44, HardenedOffset + 60, HardenedOffset, 0, 5},
			want:  "m/44'/60'/0'/0/5",
		},
		{
			name:  "single non-hardened zero",
			input: []uint32{0},
			want:  "m/0",
		},
		{
			name:  "single hardened zero",
			input: []uint32{HardenedOffset},
			want:  "m/0'",
		},
		{
			name:  "large non-hardened",
			input: []uint32{HardenedOffset - 1},
			want:  "m/2147483647",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatPath(tt.input); got != tt.want {
				t.Errorf("FormatPath(%v) = %q; want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestPathRoundTrip(t *testing.T) {
	paths := []string{
		"m",
		"m/0",
		"m/0'",
		"m/44'/60'/0'/0/0",
		"m/44'/60'/0'/0/5",
		"m/44'/60'/0'/1/999",
		"m/2147483647",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			indices, err := ParsePath(p)
			if err != nil {
				t.Fatalf("ParsePath(%q) unexpected error: %v", p, err)
			}
			if got := FormatPath(indices); got != p {
				t.Errorf("round-trip: ParsePath then FormatPath(%q) = %q", p, got)
			}
		})
	}
}
