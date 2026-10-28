package tls

import "testing"

// [eidolon] The server's CertificateVerify must use a signature algorithm the
// client offered (RFC 8446, Section 4.4.3), not just one Go supports. With
// uTLS the offered list is the spec's. BoringSSL sends illegal_parameter
// (tls12_check_peer_sigalg). Before the fix, the client accepted any
// algorithm Go supports for the key.
func TestEidolonCertificateVerifyAlgorithmOffered(t *testing.T) {
	tests := []struct {
		name      string
		sigAlg    SignatureScheme
		wantAlert alert // 0: the handshake completes
	}{
		{"offered", PSSWithSHA256, 0},
		{"not offered, PSS SHA-384", PSSWithSHA384, alertIllegalParameter},
		{"not offered, PSS SHA-512", PSSWithSHA512, alertIllegalParameter},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// eidolonTLS13Spec offers ECDSA P-256, RSA-PSS SHA-256 and
			// PKCS#1 SHA-256.
			cerr, serr := eidolonScriptedHandshake(t, eidolonTLS13Spec(), nil, eidolonServerScript{
				cert:   &testRSA2048Cert,
				sigAlg: tt.sigAlg,
			})
			if tt.wantAlert == 0 {
				eidolonExpectSuccess(t, cerr, serr)
			} else {
				eidolonExpectAlert(t, cerr, serr, tt.wantAlert)
			}
		})
	}
}
