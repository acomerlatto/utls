package tls

import (
	"errors"
	"strings"
	"testing"
)

// [eidolon] A TLS 1.2 server cannot accept ECH: as BoringSSL, the client
// that offered TLS 1.2 in ClientHelloOuter completes the handshake for
// the public name, without a client certificate or a saved session, and
// fails with an ECHRejectionError without retry configurations. uTLS
// refused TLS 1.2 with an ECHConfigList: "server selected unsupported
// protocol version 303".
func TestEidolonECHRejectedByTLS12(t *testing.T) {
	clientCert, _ := eidolonSelfSigned(t, "client.example")
	for _, tt := range []struct {
		name       string
		cert       int // in the certificates of eidolonECHServer
		minVersion uint16
		wantErr    string // empty: an ECH rejection
	}{
		{"certificate for the public name", 0, 0, ""},
		{"certificate for the inner name", 1, 0, "certificate is valid for secret.example, not public.example"},
		{"MinVersion TLS 1.3", 0, VersionTLS13, "unsupported protocol version 303"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, server := eidolonECHServer(t)
			client.MinVersion = tt.minVersion
			client.Certificates = []Certificate{clientCert}
			client.ClientSessionCache = NewLRUClientSessionCache(4)
			server.MinVersion = VersionTLS12
			server.MaxVersion = VersionTLS12
			server.Certificates = server.Certificates[tt.cert : tt.cert+1]
			server.EncryptedClientHelloKeys = nil
			server.ClientAuth = RequestClientCert
			var clientCerts int
			server.VerifyConnection = func(cs ConnectionState) error {
				clientCerts = len(cs.PeerCertificates)
				return nil
			}
			spec, err := utlsIdToSpec(HelloChrome_Auto)
			if err != nil {
				t.Fatal(err)
			}
			c, s := localPipe(t)
			serverErr := make(chan error, 1)
			go func() {
				srv := Server(s, server)
				err := srv.Handshake()
				if err == nil {
					_, err = srv.Read(make([]byte, 1))
				}
				serverErr <- err
				s.Close()
			}()
			u := UClient(c, client, HelloCustom)
			if err := u.ApplyPreset(&spec); err != nil {
				t.Fatal(err)
			}
			err = u.Handshake()
			c.Close()
			serr := <-serverErr
			var rej *ECHRejectionError
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("handshake error %v, want %q", err, tt.wantErr)
				}
				return
			}
			if !errors.As(err, &rej) || rej.RetryConfigList != nil {
				t.Fatalf("handshake error %v, want an ECH rejection without retry configurations", err)
			}
			if serr == nil || !strings.Contains(serr.Error(), "encrypted client hello required") {
				t.Errorf("server error %v, want the alert ech_required", serr)
			}
			if st := u.ConnectionState(); st.Version != VersionTLS12 {
				t.Errorf("version %x, want TLS 1.2", st.Version)
			}
			if clientCerts != 0 {
				t.Errorf("the client sent %d certificates to the public name", clientCerts)
			}
			if _, ok := client.ClientSessionCache.Get("secret.example"); ok {
				t.Error("the session of the rejected connection was saved")
			}
		})
	}
}

// [eidolon] With ECH, a TLS 1.2 ServerHello is refused when
// ClientHelloOuter did not offer TLS 1.2, and so is a TLS 1.1 one.
func TestEidolonECHServerVersion(t *testing.T) {
	for _, tt := range []struct {
		name     string
		versions []uint16 // of the outer; nil: Chrome's
		server   uint16
		wantErr  string
	}{
		{"TLS 1.2 not offered", []uint16{VersionTLS13}, VersionTLS12, "unsupported protocol version 303"},
		{"TLS 1.1", nil, VersionTLS11, "unsupported protocol version 302"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := eidolonECHServer(t)
			spec, err := utlsIdToSpec(HelloChrome_Auto)
			if err != nil {
				t.Fatal(err)
			}
			for _, ext := range spec.Extensions {
				if sv, ok := ext.(*SupportedVersionsExtension); ok && tt.versions != nil {
					sv.Versions = tt.versions
				}
			}
			cerr, _ := eidolonScriptedHandshake(t, &spec, client, eidolonServerScript{
				tls12:        true,
				tls12Version: tt.server,
				shExts:       []eidolonRawExtension{{extensionSupportedPoints, []byte{1, pointFormatUncompressed}}},
			})
			if cerr == nil || !strings.Contains(cerr.Error(), tt.wantErr) {
				t.Fatalf("client error %v, want %q", cerr, tt.wantErr)
			}
		})
	}
}
