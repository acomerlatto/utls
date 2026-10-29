package tls

import (
	"crypto/ecdh"
	"crypto/rand"
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

// eidolonECHConfigSuites returns an ECHConfig with a KEM, a public key and
// HPKE suites, as {KDF, AEAD} pairs.
func eidolonECHConfigSuites(id uint8, kem uint16, pub []byte, suites ...[2]uint16) []byte {
	var b cryptobyte.Builder
	b.AddUint16(extensionEncryptedClientHello)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(id)
		b.AddUint16(kem)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(pub) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, s := range suites {
				b.AddUint16(s[0])
				b.AddUint16(s[1])
			}
		})
		b.AddUint8(0)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("public.example")) })
		b.AddUint16(0)
	})
	return b.BytesOrPanic()
}

// [eidolon] pickECHConfig selects as BoringSSL ssl_select_ech_config: the
// first ECHConfig with DHKEM(X25519), HKDF-SHA256 and a known AEAD, the
// first such AEAD, or ChaCha20-Poly1305 without AES hardware.
func TestEidolonPickECHConfig(t *testing.T) {
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := x25519.PublicKey().Bytes()
	const (
		sha256, sha384             = 1, 2
		aes128, aes256, chacha, eo = 1, 2, 3, 0xffff
	)
	tests := []struct {
		name     string
		configs  [][]byte
		hardware bool
		id       uint8 // 0: none
		aead     uint16
	}{
		{"P-256 skipped", [][]byte{
			eidolonECHConfigSuites(1, 0x0010, p256.PublicKey().Bytes(), [2]uint16{sha256, aes128}),
			eidolonECHConfigSuites(2, 0x0020, x, [2]uint16{sha256, aes128}),
		}, true, 2, aes128},
		{"bad key skipped", [][]byte{
			eidolonECHConfigSuites(1, 0x0020, x[:31], [2]uint16{sha256, aes128}),
			eidolonECHConfigSuites(2, 0x0020, x, [2]uint16{sha256, aes128}),
		}, true, 2, aes128},
		{"HKDF-SHA384 skipped", [][]byte{
			eidolonECHConfigSuites(1, 0x0020, x, [2]uint16{sha384, aes256}, [2]uint16{sha256, aes128}),
		}, true, 1, aes128},
		{"no usable suite", [][]byte{
			eidolonECHConfigSuites(1, 0x0020, x, [2]uint16{sha384, aes128}, [2]uint16{sha256, eo}, [2]uint16{sha256, 4}),
		}, true, 0, 0},
		{"AES-256-GCM", [][]byte{
			eidolonECHConfigSuites(1, 0x0020, x, [2]uint16{sha256, aes256}, [2]uint16{sha256, aes128}),
		}, true, 1, aes256},
		{"first with AES hardware", [][]byte{
			eidolonECHConfigSuites(1, 0x0020, x, [2]uint16{sha256, aes128}, [2]uint16{sha256, chacha}),
		}, true, 1, aes128},
		{"ChaCha20 first", [][]byte{
			eidolonECHConfigSuites(1, 0x0020, x, [2]uint16{sha256, chacha}, [2]uint16{sha256, aes128}),
		}, true, 1, chacha},
		{"ChaCha20 without AES hardware", [][]byte{
			eidolonECHConfigSuites(1, 0x0020, x, [2]uint16{sha256, aes128}, [2]uint16{sha256, chacha}, [2]uint16{sha256, aes256}),
		}, false, 1, chacha},
	}
	saved := hasAESGCMHardwareSupport
	defer func() { hasAESGCMHardwareSupport = saved }()
	for _, tt := range tests {
		hasAESGCMHardwareSupport = tt.hardware
		var b cryptobyte.Builder
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, c := range tt.configs {
				b.AddBytes(c)
			}
		})
		configs, err := parseECHConfigList(b.BytesOrPanic())
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		c, _, kdf, aead := pickECHConfig(configs)
		if c == nil {
			if tt.id != 0 {
				t.Errorf("%s: no ECHConfig picked, want %d", tt.name, tt.id)
			}
			continue
		}
		if c.ConfigID != tt.id || kdf.ID() != sha256 || aead.ID() != tt.aead {
			t.Errorf("%s: picked config %d, KDF %d, AEAD %d; want %d, 1, %d", tt.name, c.ConfigID, kdf.ID(), aead.ID(), tt.id, tt.aead)
		}
	}
}
