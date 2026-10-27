package tls

import (
	"net"
	"testing"
)

// [eidolon] Regression tests for the GREASE value in signature_algorithms.
// Ported from bogdanfinn/utls (u_grease_sigalg_test.go); the substitution
// itself is upstream code in ApplyPreset.

// eidolonSigAlgGREASESpec returns a spec whose signature_algorithms starts
// with the GREASE placeholder. RFC 8701 allows GREASE there; whether a
// browser profile sends it must come from a capture, not from this test.
// ApplyPreset clones the spec, so the placeholder is replaced in the copy.
func eidolonSigAlgGREASESpec() ClientHelloSpec {
	return ClientHelloSpec{
		TLSVersMin:         VersionTLS12,
		TLSVersMax:         VersionTLS13,
		CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		CompressionMethods: []uint8{compressionNone},
		Extensions: []TLSExtension{
			&SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []SignatureScheme{
					SignatureScheme(GREASE_PLACEHOLDER),
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
				},
			},
		},
	}
}

// eidolonApplySigAlgGREASESpec applies a new spec to a new connection and
// returns the connection and the signature algorithms ApplyPreset wrote.
func eidolonApplySigAlgGREASESpec(t *testing.T) (*UConn, []SignatureScheme) {
	t.Helper()
	spec := eidolonSigAlgGREASESpec()
	u := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloCustom)
	if err := u.ApplyPreset(&spec); err != nil {
		t.Fatal(err)
	}
	for _, ext := range u.Extensions {
		if e, ok := ext.(*SignatureAlgorithmsExtension); ok {
			return u, e.SupportedSignatureAlgorithms
		}
	}
	t.Fatal("signature_algorithms extension not found")
	return nil, nil
}

// The placeholder is replaced by a real GREASE value, drawn again for each
// connection, and the other algorithms are kept. A constant 0x0a0a on every
// connection is a reliable "not Chrome" signal.
func TestEidolonSigAlgGREASESubstitution(t *testing.T) {
	const connections = 64
	values := make(map[SignatureScheme]bool)
	for range connections {
		_, sigAlgs := eidolonApplySigAlgGREASESpec(t)
		if len(sigAlgs) != 4 {
			t.Fatalf("signature_algorithms has %d entries, want 4", len(sigAlgs))
		}
		if !isGREASEUint16(uint16(sigAlgs[0])) {
			t.Fatalf("signature_algorithms[0] = %#04x, not a GREASE value", uint16(sigAlgs[0]))
		}
		if sigAlgs[1] != ECDSAWithP256AndSHA256 || sigAlgs[2] != PSSWithSHA256 || sigAlgs[3] != PKCS1WithSHA256 {
			t.Fatalf("non-GREASE algorithms rewritten: %#04x, %#04x, %#04x",
				uint16(sigAlgs[1]), uint16(sigAlgs[2]), uint16(sigAlgs[3]))
		}
		values[sigAlgs[0]] = true
	}
	// 64 draws from 16 values: asking for more than one distinct value catches
	// a constant without failing on an unlucky run.
	if len(values) < 2 {
		t.Errorf("%d connections produced %d distinct GREASE values", connections, len(values))
	}
}

// The value comes from the per-connection seed, at the index reserved for
// signature algorithms, as in BoringSSL.
func TestEidolonSigAlgGREASEMatchesSeed(t *testing.T) {
	u, sigAlgs := eidolonApplySigAlgGREASESpec(t)
	want := SignatureScheme(getBoringGREASEValue(u.greaseSeed[:], ssl_grease_signature_algorithm))
	if sigAlgs[0] != want {
		t.Errorf("signature_algorithms[0] = %#04x, want seeded value %#04x", uint16(sigAlgs[0]), uint16(want))
	}
}
