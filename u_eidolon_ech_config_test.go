package tls

import (
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
