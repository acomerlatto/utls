package tls

import (
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// [eidolon] parseECHConfigList refuses a list BoringSSL refuses
// (ssl_is_valid_ech_config_list), as SSL_set1_ech_config_list does for
// Chrome. uTLS read each ECHConfig past its contents and accepted trailing
// bytes or a field of the next ECHConfig, and a list whose length did not
// fit in 16 bits made it loop forever.
func TestEidolonParseECHConfigList(t *testing.T) {
	if configs, err := parseECHConfigList(eidolonECHConfigList(t, nil)); err != nil || len(configs) != 1 {
		t.Fatalf("valid list: %d configs, %v", len(configs), err)
	}
	// An ECHConfig of 65532 bytes in a list whose length, 65536, does not fit
	// its 16-bit field.
	huge := make([]byte, 2+65536)
	huge[2], huge[3] = 0xfe, 0x0d
	huge[4], huge[5] = 0xff, 0xfc
	for name, list := range map[string][]byte{
		"trailing contents": eidolonECHConfigList(t, func(b *cryptobyte.Builder) { b.AddUint8(0) }),
		"length overflow":   huge,
	} {
		if _, err := parseECHConfigList(list); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// [eidolon] The public name follows BoringSSL ssl_is_valid_ech_public_name.
func TestEidolonECHPublicName(t *testing.T) {
	for name, want := range map[string]bool{
		"public.example":        true,
		"localhost":             true,
		"a-b.example":           true,
		"x.1a":                  true,
		"x.0xg":                 true,
		"x.1x5":                 true,
		strings.Repeat("a", 63): true,
		"":                      false,
		".example":              false,
		"example.":              false,
		"a..example":            false,
		"-a.example":            false,
		"a-.example":            false,
		"a_b.example":           false,
		strings.Repeat("a", 64): false,
		"127.0.0.1":             false,
		"127.1":                 false,
		"example.42":            false,
		"example.0x":            false,
		"example.0XfF":          false,
		"exa mple.com":          false,
	} {
		if got := validDNSName(name); got != want {
			t.Errorf("validDNSName(%q) = %v, want %v", name, got, want)
		}
	}
	// A configuration with an IPv4 public name is skipped.
	for name, want := range map[string]bool{"public.example": true, "127.1": false} {
		_, list := eidolonECHConfig(1, make([]byte, 32), name)
		configs, err := parseECHConfigList(list)
		if err != nil {
			t.Fatal(err)
		}
		if c, _, _, _ := pickECHConfig(configs); (c != nil) != want {
			t.Errorf("%s: picked %v, want %v", name, c != nil, want)
		}
	}
}
