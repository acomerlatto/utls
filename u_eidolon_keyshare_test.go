package tls

import (
	"testing"
	"time"
)

// [eidolon] The server may select any key share the client offered, not only
// the first classical one. Before the fix, the client always used the key of
// the first classical share and failed with "invalid server key share".
func TestEidolonKeyShareSelectedByServer(t *testing.T) {
	tests := []struct {
		name      string
		keyShares []KeyShare
		server    []CurveID
		want      CurveID
	}{
		{
			name:      "second classical share",
			keyShares: []KeyShare{{Group: X25519}, {Group: CurveP256}},
			server:    []CurveID{CurveP256},
			want:      CurveP256,
		},
		{
			name:      "first classical share",
			keyShares: []KeyShare{{Group: X25519}, {Group: CurveP256}},
			server:    []CurveID{X25519},
			want:      X25519,
		},
		{
			name:      "second classical share is X25519",
			keyShares: []KeyShare{{Group: CurveP256}, {Group: X25519}},
			server:    []CurveID{X25519},
			want:      X25519,
		},
		{
			name:      "hybrid then two classical, server picks the last",
			keyShares: []KeyShare{{Group: X25519MLKEM768}, {Group: X25519}, {Group: CurveP256}},
			server:    []CurveID{CurveP256},
			want:      CurveP256,
		},
		{
			name:      "hybrid then two classical, server picks the hybrid",
			keyShares: []KeyShare{{Group: X25519MLKEM768}, {Group: X25519}, {Group: CurveP256}},
			server:    []CurveID{X25519MLKEM768},
			want:      X25519MLKEM768,
		},
		{
			name: "reused hybrid key, server picks the classical share",
			keyShares: append(
				ReuseHybridAndClassicalKeyShares(KeyShare{Group: X25519MLKEM768}, KeyShare{Group: X25519}),
				KeyShare{Group: CurveP256},
			),
			server: []CurveID{X25519},
			want:   X25519,
		},
		{
			name: "reused hybrid key, server picks P-256",
			keyShares: append(
				ReuseHybridAndClassicalKeyShares(KeyShare{Group: X25519MLKEM768}, KeyShare{Group: X25519}),
				KeyShare{Group: CurveP256},
			),
			server: []CurveID{CurveP256},
			want:   CurveP256,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eidolonHandshakeWithKeyShares(t, tt.keyShares, tt.server)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("curve = %v, want %v", got, tt.want)
			}
		})
	}
}

func eidolonHandshakeWithKeyShares(t *testing.T, keyShares []KeyShare, serverCurves []CurveID) (CurveID, error) {
	t.Helper()
	c, s := localPipe(t)
	defer c.Close()
	defer s.Close()
	deadline := time.Now().Add(10 * time.Second)
	c.SetDeadline(deadline)
	s.SetDeadline(deadline)

	srvCfg := testConfigServer.Clone()
	srvCfg.CurvePreferences = serverCurves
	srvCfg.MinVersion = VersionTLS13
	errc := make(chan error, 1)
	go func() {
		err := Server(s, srvCfg).Handshake()
		if err != nil {
			s.Close()
		}
		errc <- err
	}()

	curves := make([]CurveID, len(keyShares))
	for i, ks := range keyShares {
		curves[i] = ks.Group
	}
	spec := ClientHelloSpec{
		TLSVersMin:         VersionTLS13,
		TLSVersMax:         VersionTLS13,
		CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		CompressionMethods: []uint8{compressionNone},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&SupportedCurvesExtension{Curves: curves},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256}},
			&KeyShareExtension{KeyShares: keyShares},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
		},
	}
	u := UClient(c, testConfigClient.Clone(), HelloCustom)
	if err := u.ApplyPreset(&spec); err != nil {
		t.Fatal(err)
	}
	cerr := u.Handshake()
	if cerr != nil {
		c.Close()
	}
	serr := <-errc
	if cerr != nil {
		t.Logf("server: %v", serr)
		return 0, cerr
	}
	if serr != nil {
		return 0, serr
	}
	return u.ConnectionState().CurveID, nil
}
