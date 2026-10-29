package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// eidolonECHConfig returns an ECHConfig for DHKEM(X25519, HKDF-SHA256),
// HKDF-SHA256 and AES-128-GCM, and the ECHConfigList that holds only it.
func eidolonECHConfig(id uint8, pub []byte, publicName string) (config, list []byte) {
	var b cryptobyte.Builder
	b.AddUint16(extensionEncryptedClientHello)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(id)
		b.AddUint16(0x0020)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(pub) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(1) })
		b.AddUint8(32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(publicName)) })
		b.AddUint16(0)
	})
	config = b.BytesOrPanic()
	var l cryptobyte.Builder
	l.AddUint16LengthPrefixed(func(l *cryptobyte.Builder) { l.AddBytes(config) })
	return config, l.BytesOrPanic()
}

// eidolonSelfSigned returns a self-signed certificate for name.
func eidolonSelfSigned(t *testing.T, name string) (Certificate, *x509.Certificate) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return Certificate{Certificate: [][]byte{der}, PrivateKey: k}, cert
}

// [eidolon] When the server cannot decrypt the ClientHelloInner, the
// handshake runs with ClientHelloOuter, whose name is the public name of the
// ECHConfig, and the client authenticates the server for that name before it
// trusts the retry configs (RFC 9849, Section 6.1.7), as Go's crypto/tls and
// BoringSSL (SSL_get0_ech_name_override) do. uTLS verified the certificate
// against Config.ServerName, the name of the ClientHelloInner: a certificate
// for the public name failed and one for the inner name authenticated the
// rejection. InsecureServerNameToVerify, which replaces the inner name,
// does not apply either.
func TestEidolonECHRejectionVerifiesPublicName(t *testing.T) {
	publicCert, publicX509 := eidolonSelfSigned(t, "public.example")
	secretCert, secretX509 := eidolonSelfSigned(t, "secret.example")

	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, clientList := eidolonECHConfig(1, clientKey.PublicKey().Bytes(), "public.example")
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, retryList := eidolonECHConfig(2, serverKey.PublicKey().Bytes(), "public.example")

	chrome, err := utlsIdToSpec(HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name         string
		serverCert   Certificate
		insecureName string // InsecureServerNameToVerify
		wantReject   bool   // false: certificate error
	}{
		{"certificate for the public name", publicCert, "", true},
		{"certificate for the inner name", secretCert, "", false},
		{"any inner name", secretCert, "*", false},
		{"other inner name", publicCert, "secret.example", true},
	} {
		for _, spec := range []*ClientHelloSpec{nil, &chrome} {
			name := tt.name + "/Go"
			if spec != nil {
				name = tt.name + "/Chrome"
			}
			t.Run(name, func(t *testing.T) {
				cfg := &Config{
					ServerName:                     "secret.example",
					RootCAs:                        x509.NewCertPool(),
					MinVersion:                     VersionTLS13,
					EncryptedClientHelloConfigList: clientList,
					InsecureServerNameToVerify:     tt.insecureName,
				}
				cfg.RootCAs.AddCert(publicX509)
				cfg.RootCAs.AddCert(secretX509)
				srv := &Config{
					Certificates:             []Certificate{tt.serverCert},
					MinVersion:               VersionTLS13,
					EncryptedClientHelloKeys: []EncryptedClientHelloKey{{Config: serverConfig, PrivateKey: serverKey.Bytes(), SendAsRetry: true}},
				}
				c, s := localPipe(t)
				go func() {
					Server(s, srv).Handshake()
					s.Close()
				}()
				var cerr error
				if spec == nil {
					cerr = Client(c, cfg).Handshake()
				} else {
					u := UClient(c, cfg, HelloCustom)
					if err := u.ApplyPreset(spec); err != nil {
						t.Fatal(err)
					}
					cerr = u.Handshake()
				}
				c.Close()
				var rej *ECHRejectionError
				var cve *CertificateVerificationError
				switch {
				case tt.wantReject && !errors.As(cerr, &rej):
					t.Fatalf("client error = %v, want ECHRejectionError", cerr)
				case tt.wantReject && !bytes.Equal(rej.RetryConfigList, retryList):
					t.Fatalf("retry configs = %x, want %x", rej.RetryConfigList, retryList)
				case !tt.wantReject && !errors.As(cerr, &cve):
					t.Fatalf("client error = %v, want CertificateVerificationError", cerr)
				}
			})
		}
	}
}
