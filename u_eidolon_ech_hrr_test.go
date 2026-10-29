package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net"
	"sync"
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

// eidolonWriteRecorder records the bytes written to a connection.
type eidolonWriteRecorder struct {
	net.Conn
	mu      sync.Mutex
	written []byte
}

func (r *eidolonWriteRecorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	r.written = append(r.written, b...)
	r.mu.Unlock()
	return r.Conn.Write(b)
}

// helloECHExtensions returns the encrypted_client_hello extension of each
// ClientHello in the plaintext handshake records of raw.
func helloECHExtensions(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	var handshake []byte
	for len(raw) >= 5 && recordType(raw[0]) != recordTypeApplicationData {
		n := int(raw[3])<<8 | int(raw[4])
		if recordType(raw[0]) == recordTypeHandshake {
			handshake = append(handshake, raw[5:5+n]...)
		}
		raw = raw[5+n:]
	}
	var exts [][]byte
	for len(handshake) >= 4 {
		n := 4 + (int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3]))
		if n > len(handshake) {
			break
		}
		if handshake[0] == typeClientHello {
			m := &clientHelloMsg{}
			if !m.unmarshal(handshake[:n]) {
				t.Fatal("cannot parse a ClientHello")
			}
			exts = append(exts, m.encryptedClientHello)
		}
		handshake = handshake[n:]
	}
	return exts
}

// [eidolon] After a HelloRetryRequest that rejects ECH, the second
// ClientHelloOuter carries the encrypted_client_hello extension of the
// first, as BoringSSL sends it (do_send_second_client_hello encrypts again
// only when ECH was accepted). uTLS sent the GREASE ECH extension of the
// spec instead.
func TestEidolonECHRejectedHelloRetryRequest(t *testing.T) {
	client, server := eidolonECHServer(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config, _ := eidolonECHConfig(2, key.PublicKey().Bytes(), "public.example")
	server.EncryptedClientHelloKeys = []EncryptedClientHelloKey{{Config: config, PrivateKey: key.Bytes(), SendAsRetry: true}}
	server.CurvePreferences = []CurveID{CurveP384}
	spec, err := utlsIdToSpec(HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	c, s := localPipe(t)
	go func() {
		Server(s, server).Handshake()
		s.Close()
	}()
	rec := &eidolonWriteRecorder{Conn: c}
	u := UClient(rec, client, HelloCustom)
	if err := u.ApplyPreset(&spec); err != nil {
		t.Fatal(err)
	}
	err = u.Handshake()
	c.Close()
	var rej *ECHRejectionError
	if !errors.As(err, &rej) || !u.ConnectionState().HelloRetryRequest {
		t.Fatalf("handshake error %v, HRR %v; want an ECH rejection after HRR", err, u.ConnectionState().HelloRetryRequest)
	}
	rec.mu.Lock()
	exts := helloECHExtensions(t, rec.written)
	rec.mu.Unlock()
	if len(exts) != 2 {
		t.Fatalf("%d ClientHellos, want 2", len(exts))
	}
	// type outer, HKDF-SHA256, AES-128-GCM, config_id 1
	if !bytes.HasPrefix(exts[0], []byte{0, 0, 1, 0, 1, 1}) {
		t.Errorf("first ECH extension %x is not for config 1", exts[0][:6])
	}
	if !bytes.Equal(exts[1], exts[0]) {
		t.Errorf("second ECH extension differs from the first:\n%x\n%x", exts[1], exts[0])
	}
}
