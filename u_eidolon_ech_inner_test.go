package tls

import (
	"bytes"
	"slices"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// eidolonOuterExtensions returns the extension types of a marshaled
// ClientHello, in order.
func eidolonOuterExtensions(t *testing.T, raw []byte) []uint16 {
	t.Helper()
	m := &clientHelloMsg{}
	if !m.unmarshal(raw) {
		t.Fatal("cannot parse the ClientHello")
	}
	exts, err := extractRawExtensions(m)
	if err != nil {
		t.Fatal(err)
	}
	var types []uint16
	for _, e := range exts {
		types = append(types, e.extType)
	}
	return types
}

// eidolonWantInner returns the extension types of ClientHelloInner as
// BoringSSL builds them from a Chrome ClientHelloOuter with these types:
// server_name, encrypted_client_hello and supported_versions in place, the
// TLS 1.2 extensions left out, and the compressed ones last, in order.
func eidolonWantInner(outer []uint16) []uint16 {
	var plain, compressed []uint16
	for _, typ := range outer {
		switch typ {
		case extensionServerName, extensionEncryptedClientHello, extensionSupportedVersions:
			plain = append(plain, typ)
		case extensionExtendedMasterSecret, extensionRenegotiationInfo, extensionSessionTicket,
			extensionSupportedPoints, utlsExtensionPadding:
		default:
			compressed = append(compressed, typ)
		}
	}
	return append(plain, compressed...)
}

// [eidolon] ClientHelloInner has the shape of BoringSSL's: the server that
// decrypts it sees the cipher suites, versions and extensions of Chrome,
// not those of Go's makeClientHello.
func TestEidolonECHInnerShape(t *testing.T) {
	client, server := eidolonECHServer(t)
	hello, u, err := eidolonECHHandshake(t, client, server)
	if err != nil {
		t.Fatal(err)
	}
	if !u.ConnectionState().ECHAccepted {
		t.Fatal("ECH not accepted")
	}
	outer := u.HandshakeState.Hello
	if hello.ServerName != "secret.example" {
		t.Errorf("inner server name = %q, want secret.example", hello.ServerName)
	}
	var wantSuites []uint16
	for _, id := range outer.CipherSuites {
		if isGREASEUint16(id) || cipherSuiteTLS13ByID(id) != nil {
			wantSuites = append(wantSuites, id)
		}
	}
	if len(wantSuites) != 4 || !slices.Equal(hello.CipherSuites, wantSuites) {
		t.Errorf("inner cipher suites = %x, want %x", hello.CipherSuites, wantSuites)
	}
	if len(hello.SupportedVersions) != 2 || !isGREASEUint16(hello.SupportedVersions[0]) || hello.SupportedVersions[1] != VersionTLS13 {
		t.Errorf("inner versions = %x, want GREASE and TLS 1.3", hello.SupportedVersions)
	}
	// The handshake checks the ServerHello against the inner it sent.
	if sent := u.echCtx.innerHello; !slices.Equal(sent.cipherSuites, hello.CipherSuites) {
		t.Errorf("inner kept by the client has cipher suites %x, want %x", sent.cipherSuites, hello.CipherSuites)
	}
	outerTypes := eidolonOuterExtensions(t, outer.Raw)
	if want := eidolonWantInner(outerTypes); !slices.Equal(hello.Extensions, want) {
		t.Errorf("inner extensions = %d\nwant %d\nouter %d", hello.Extensions, want, outerTypes)
	}
}

// [eidolon] EncodedClientHelloInner names the compressed extensions in
// ech_outer_extensions, is padded to a multiple of 32 bytes, and the
// server's decoder rebuilds ClientHelloInner from it, byte for byte.
func TestEidolonECHInnerEncoding(t *testing.T) {
	spec, err := utlsIdToSpec(HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	u := UClient(nil, &Config{ServerName: "secret.example"}, HelloCustom)
	if err := u.ApplyPreset(&spec); err != nil {
		t.Fatal(err)
	}
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	outerRaw := u.HandshakeState.Hello.Raw
	random := bytes.Repeat([]byte{7}, 32)
	for _, name := range []string{"secret.example", ""} {
		inner, encoded, err := echInner(outerRaw, random, name, 32)
		if err != nil {
			t.Fatal(err)
		}
		if len(encoded)%32 != 0 {
			t.Errorf("%q: encoded length %d is not a multiple of 32", name, len(encoded))
		}
		outer := &clientHelloMsg{}
		if !outer.unmarshal(outerRaw) {
			t.Fatal("cannot parse the outer")
		}
		decoded, err := decodeInnerClientHello(outer, encoded)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		if !bytes.Equal(decoded.original, inner) {
			t.Errorf("%q: decoded inner differs from ClientHelloInner", name)
		}
		s := cryptobyte.String(encoded)
		var sessionID []byte
		if !s.Skip(2+32) || !readUint8LengthPrefixed(&s, &sessionID) || len(sessionID) != 0 {
			t.Errorf("%q: encoded inner has a session ID", name)
		}
		if !bytes.Contains(encoded, []byte{0xfd, 0x00}) {
			t.Errorf("%q: no ech_outer_extensions", name)
		}
		if got := decoded.serverName; got != name {
			t.Errorf("inner server name = %q, want %q", got, name)
		}
		if decoded.vers != VersionTLS12 || !bytes.Equal(decoded.random, random) {
			t.Errorf("%q: inner legacy_version %x, random %x", name, decoded.vers, decoded.random)
		}
	}
}

// [eidolon] The padding of EncodedClientHelloInner follows RFC 9849,
// Section 6.1.3: up to maximum_name_length for the name, or the name and
// its extension overhead without one, then to a multiple of 32 bytes.
func TestEidolonECHInnerPadding(t *testing.T) {
	spec, err := utlsIdToSpec(HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	u := UClient(nil, &Config{ServerName: "secret.example"}, HelloCustom)
	if err := u.ApplyPreset(&spec); err != nil {
		t.Fatal(err)
	}
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"secret.example", ""} {
		_, unpadded, err := echInner(u.HandshakeState.Hello.Raw, make([]byte, 32), name, 0)
		if err != nil {
			t.Fatal(err)
		}
		unpadded = bytes.TrimRight(unpadded, "\x00")
		for maxLen := 0; maxLen < 64; maxLen++ {
			_, encoded, err := echInner(u.HandshakeState.Hello.Raw, make([]byte, 32), name, maxLen)
			if err != nil {
				t.Fatal(err)
			}
			pad := max(0, maxLen-len(name))
			if name == "" {
				pad = maxLen + 9
			}
			want := (len(unpadded) + pad + 31) / 32 * 32
			if len(encoded) != want {
				t.Fatalf("%q, maximum_name_length %d: encoded length %d, want %d", name, maxLen, len(encoded), want)
			}
		}
	}
}

// eidolonRawHello marshals a ClientHello with cipher suites and extensions.
func eidolonRawHello(suites []uint16, exts []eidolonRawExtension) []byte {
	var b cryptobyte.Builder
	b.AddUint8(typeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(VersionTLS12)
		b.AddBytes(make([]byte, 32))
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(bytes.Repeat([]byte{9}, 32)) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, id := range suites {
				b.AddUint16(id)
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(compressionNone) })
		eidolonAddExtensions(b, exts)
	})
	return b.BytesOrPanic()
}

// [eidolon] Each extension of ClientHelloOuter goes into ClientHelloInner
// as BoringSSL puts it: left out, compressed or copied.
func TestEidolonECHInnerExtensions(t *testing.T) {
	sni := []byte{0, 17, 0, 0, 14, 'p', 'u', 'b', 'l', 'i', 'c', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'}
	outer := eidolonRawHello([]uint16{0x0a0a, TLS_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384}, []eidolonRawExtension{
		{0x0a0a, nil},
		{extensionServerName, sni},
		{extensionExtendedMasterSecret, nil},
		{extensionRenegotiationInfo, []byte{0}},
		{extensionSessionTicket, nil},
		{extensionSupportedPoints, []byte{1, 0}},
		{extensionNextProtoNeg, nil},
		{fakeExtensionChannelID, nil},
		{extensionEarlyData, nil},
		{extensionCookie, []byte{0, 2, 'c', 'k'}},
		{utlsExtensionApplicationSettings, []byte{0, 3, 2, 'h', '2'}},
		{extensionCertificateAuthorities, []byte{0, 0}},
		{28, []byte{0x40, 0x01}},
		{extensionSupportedVersions, []byte{6, 0x1a, 0x1a, 3, 4, 3, 3}},
		{extensionEncryptedClientHello, []byte{0, 1, 2, 3}},
		{utlsExtensionPadding, make([]byte, 7)},
		{extensionPreSharedKey, []byte{0, 0}},
	})
	inner, _, err := echInner(outer, make([]byte, 32), "secret.example", 0)
	if err != nil {
		t.Fatal(err)
	}
	m := &clientHelloMsg{}
	if !m.unmarshal(inner) {
		t.Fatal("cannot parse ClientHelloInner")
	}
	if want := []uint16{0x0a0a, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384}; !slices.Equal(m.cipherSuites, want) {
		t.Errorf("cipher suites = %x, want %x", m.cipherSuites, want)
	}
	if want := []uint16{0x1a1a, VersionTLS13}; !slices.Equal(m.supportedVersions, want) {
		t.Errorf("versions = %x, want %x", m.supportedVersions, want)
	}
	if m.serverName != "secret.example" || !bytes.Equal(m.encryptedClientHello, []byte{1}) {
		t.Errorf("server name %q, encrypted_client_hello %x", m.serverName, m.encryptedClientHello)
	}
	want := []uint16{
		extensionServerName, 28, extensionSupportedVersions, extensionEncryptedClientHello,
		0x0a0a, extensionEarlyData, extensionCookie, utlsExtensionApplicationSettings, extensionCertificateAuthorities,
	}
	if got := eidolonOuterExtensions(t, inner); !slices.Equal(got, want) {
		t.Errorf("inner extensions = %d, want %d", got, want)
	}
}
