package tls

import (
	"bytes"
	"testing"
)

// [eidolon] Server ALPS (application_settings) is accepted only on the
// codepoint the client sent and for a negotiated protocol the client offered
// ALPS for, as in BoringSSL. Before the fix, the client accepted ALPS on the
// other codepoint and for any protocol, and then sent empty settings back.
func TestEidolonALPSMustMatchOffer(t *testing.T) {
	settings := []byte("server settings")
	tests := []struct {
		name      string
		newCode   bool   // the client sends ALPS on the new codepoint
		serverExt uint16 // codepoint the server answers on
		alpn      string
		wantAlert alert // 0: the handshake completes
	}{
		{"old codepoint", false, utlsExtensionApplicationSettings, "h2", 0},
		{"new codepoint", true, utlsExtensionApplicationSettingsNew, "h2", 0},
		{"new codepoint answered, old sent", false, utlsExtensionApplicationSettingsNew, "h2", alertUnsupportedExtension},
		{"old codepoint answered, new sent", true, utlsExtensionApplicationSettings, "h2", alertUnsupportedExtension},
		{"protocol without ALPS offer", false, utlsExtensionApplicationSettings, "http/1.1", alertIllegalParameter},
		{"no ALPN negotiated", false, utlsExtensionApplicationSettings, "", alertIllegalParameter},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var alps TLSExtension = &ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}}
			if tt.newCode {
				alps = &ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}
			}
			spec := eidolonTLS13Spec(&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}, alps)
			config := testConfigClient.Clone()
			config.ApplicationSettings = map[string][]byte{"h2": []byte("client settings")}

			u, cerr, serr := eidolonScriptedConn(t, spec, config, eidolonServerScript{
				alpn:   tt.alpn,
				eeExts: []eidolonRawExtension{{tt.serverExt, settings}},
			})
			if tt.wantAlert != 0 {
				eidolonExpectAlert(t, cerr, serr, tt.wantAlert)
				return
			}
			eidolonExpectSuccess(t, cerr, serr)
			if got := u.ConnectionState().PeerApplicationSettings; !bytes.Equal(got, settings) {
				t.Errorf("PeerApplicationSettings = %q, want %q", got, settings)
			}
		})
	}
}
