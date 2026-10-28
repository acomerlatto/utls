package tls

import "testing"

// [eidolon] With GREASE ECH, a server that supports ECH but cannot decrypt
// the ClientHello may put 8 random bytes in the encrypted_client_hello
// extension of a HelloRetryRequest (RFC 9849, Section 7.1). The client checks
// the syntax and otherwise ignores it (Section 6.2.1), as BoringSSL does.
// Before the fix, the client aborted with unsupported_extension.
func TestEidolonGREASEECHHelloRetryRequest(t *testing.T) {
	tests := []struct {
		name      string
		greaseECH bool
		ech       []byte
		wantAlert alert // 0: the handshake completes
	}{
		{"GREASE ECH, 8 bytes", true, []byte("8 random"), 0},
		{"GREASE ECH, 7 bytes", true, []byte("7 bytes"), alertDecodeError},
		{"GREASE ECH, 9 bytes", true, []byte("9 random!"), alertDecodeError},
		{"GREASE ECH, empty", true, []byte{}, alertDecodeError},
		{"no ECH offered", false, []byte("8 random"), alertUnsupportedExtension},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var extra []TLSExtension
			if tt.greaseECH {
				extra = append(extra, BoringGREASEECH())
			}
			cerr, serr := eidolonScriptedHandshake(t, eidolonTLS13Spec(extra...), nil, eidolonServerScript{
				hrrExts: []eidolonRawExtension{{extensionEncryptedClientHello, tt.ech}},
			})
			if tt.wantAlert == 0 {
				eidolonExpectSuccess(t, cerr, serr)
			} else {
				eidolonExpectAlert(t, cerr, serr, tt.wantAlert)
			}
		})
	}
}
