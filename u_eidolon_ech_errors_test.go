package tls

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// [eidolon] A client tells a malformed ECHConfigList from one without a
// usable ECHConfig, as Chrome does with BoringSSL: the first fails
// SSL_set1_ech_config_list, the second only the selection, which Chrome
// answers with GREASE ECH unless ECH is required.
func TestEidolonECHConfigListErrors(t *testing.T) {
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var unusable cryptobyte.Builder
	unusable.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(eidolonECHConfigSuites(1, 0x0010, p256.PublicKey().Bytes(), [2]uint16{1, 1}))
	})
	for name, tt := range map[string]struct {
		list        []byte
		want, other error
	}{
		"malformed": {eidolonECHConfigList(t, func(b *cryptobyte.Builder) { b.AddUint8(0) }), ErrMalformedECHConfigList, ErrNoUsableECHConfig},
		"unusable":  {unusable.BytesOrPanic(), ErrNoUsableECHConfig, ErrMalformedECHConfigList},
	} {
		for _, std := range []bool{false, true} {
			config := &Config{ServerName: "example.com", EncryptedClientHelloConfigList: tt.list}
			if std {
				_, _, _, err = (&Conn{config: config}).makeClientHello()
			} else {
				err = UClient(nil, config, HelloChrome_Auto).BuildHandshakeState()
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("%s (std %v): %v, want %v", name, std, err, tt.want)
			}
			if errors.Is(err, tt.other) {
				t.Errorf("%s (std %v): also %v", name, std, tt.other)
			}
		}
	}
}
