package tls

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

// eidolonECHServer returns a client config for secret.example with an
// ECHConfigList and a server config that accepts it.
func eidolonECHServer(t *testing.T) (client, server *Config) {
	t.Helper()
	publicCert, publicX509 := eidolonSelfSigned(t, "public.example")
	secretCert, secretX509 := eidolonSelfSigned(t, "secret.example")
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config, list := eidolonECHConfig(1, key.PublicKey().Bytes(), "public.example")
	client = &Config{
		ServerName:                     "secret.example",
		RootCAs:                        x509.NewCertPool(),
		EncryptedClientHelloConfigList: list,
	}
	client.RootCAs.AddCert(publicX509)
	client.RootCAs.AddCert(secretX509)
	server = &Config{
		Certificates:             []Certificate{publicCert, secretCert},
		MinVersion:               VersionTLS13,
		EncryptedClientHelloKeys: []EncryptedClientHelloKey{{Config: config, PrivateKey: key.Bytes(), SendAsRetry: true}},
	}
	return client, server
}

// eidolonECHHandshake runs a Chrome handshake with ECH against server and
// returns the ClientHello the server read last, the client and the
// client error.
func eidolonECHHandshake(t *testing.T, client, server *Config) (*ClientHelloInfo, *UConn, error) {
	t.Helper()
	spec, err := utlsIdToSpec(HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	var hello *ClientHelloInfo
	server = server.Clone()
	server.GetConfigForClient = func(chi *ClientHelloInfo) (*Config, error) {
		hello = chi
		return nil, nil
	}
	c, s := localPipe(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		Server(s, server).Handshake()
		s.Close()
	}()
	u := UClient(c, client, HelloCustom)
	if err := u.ApplyPreset(&spec); err != nil {
		t.Fatal(err)
	}
	err = u.Handshake()
	c.Close()
	<-done
	return hello, u, err
}

// [eidolon] After a HelloRetryRequest, the second ClientHelloOuter carries
// the new key share, which ClientHelloInner compresses: uTLS set the outer
// key_share extension from the outer's old key shares, so the server
// decompressed a key share for the wrong group.
func TestEidolonECHHelloRetryRequest(t *testing.T) {
	client, server := eidolonECHServer(t)
	server.CurvePreferences = []CurveID{CurveP384}
	hello, u, err := eidolonECHHandshake(t, client, server)
	if err != nil {
		t.Fatal(err)
	}
	st := u.ConnectionState()
	if !st.ECHAccepted || !st.HelloRetryRequest || st.CurveID != CurveP384 {
		t.Fatalf("ECH accepted %v, HRR %v, group %v; want an accepted ECH after HRR to P-384", st.ECHAccepted, st.HelloRetryRequest, st.CurveID)
	}
	if hello.ServerName != "secret.example" {
		t.Errorf("inner server name = %q, want secret.example", hello.ServerName)
	}
}
