package tls

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// eidolonTicketCache records the session tickets a client stores.
type eidolonTicketCache struct {
	mu   sync.Mutex
	puts int
}

func (c *eidolonTicketCache) Get(string) (*ClientSessionState, bool) { return nil, false }
func (c *eidolonTicketCache) Put(_ string, cs *ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cs != nil {
		c.puts++
	}
}

// eidolonALPSHandshake runs a UConn whose spec offers ALPN alpn and the
// ALPS extension alps (none for nil) against a uTLS server that negotiates
// serverALPN with serverSettings. The server writes one byte after the
// handshake, which the client reads, with the session ticket before it.
func eidolonALPSHandshake(t *testing.T, alpn []string, alps TLSExtension, serverALPN []string, serverSettings map[string][]byte) (client, server ConnectionState, tickets int) {
	t.Helper()
	c, s := localPipe(t)
	defer c.Close()
	defer s.Close()
	deadline := time.Now().Add(10 * time.Second)
	c.SetDeadline(deadline)
	s.SetDeadline(deadline)

	srvCfg := testConfigServer.Clone()
	srvCfg.MinVersion = VersionTLS13
	srvCfg.NextProtos = serverALPN
	srvCfg.ApplicationSettings = serverSettings
	type result struct {
		state ConnectionState
		err   error
	}
	done := make(chan result, 1)
	go func() {
		srv := Server(s, srvCfg)
		err := srv.Handshake()
		if err == nil {
			_, err = srv.Write([]byte("x"))
		}
		if err != nil {
			s.Close()
		}
		done <- result{srv.ConnectionState(), err}
	}()

	extra := []TLSExtension{&ALPNExtension{AlpnProtocols: alpn}, &PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}}}
	if alps != nil {
		extra = append(extra, alps)
	}
	cfg := testConfigClient.Clone()
	cfg.ApplicationSettings = map[string][]byte{"h2": []byte("client settings")}
	cache := &eidolonTicketCache{}
	cfg.ClientSessionCache = cache
	u := UClient(c, cfg, HelloCustom)
	if err := u.ApplyPreset(eidolonTLS13Spec(extra...)); err != nil {
		t.Fatal(err)
	}
	if err := u.Handshake(); err != nil {
		c.Close()
		t.Fatalf("client: %v (server: %v)", err, (<-done).err)
	}
	if _, err := io.ReadFull(u, make([]byte, 1)); err != nil {
		t.Fatalf("client read: %v", err)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("server: %v", r.err)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return u.ConnectionState(), r.state, cache.puts
}

// [eidolon] A uTLS server negotiates ALPS as BoringSSL's
// ssl_negotiate_alps: on the codepoint of the ClientHello, when the client
// offers it for the negotiated protocol and the server has settings for
// it. The client then sends its settings in its EncryptedExtensions, which
// the server reads before the session ticket; without ALPS, nothing
// changes.
func TestEidolonServerALPS(t *testing.T) {
	h2 := map[string][]byte{"h2": []byte("server settings")}
	for _, tt := range []struct {
		name           string
		alps           TLSExtension
		serverALPN     []string
		serverSettings map[string][]byte
		want           bool
	}{
		{"new codepoint", &ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}, []string{"h2"}, h2, true},
		{"old codepoint", &ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}}, []string{"h2"}, h2, true},
		{"empty settings", &ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}, []string{"h2"}, map[string][]byte{"h2": {}}, true},
		{"no server settings", &ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}, []string{"h2"}, nil, false},
		{"settings for another protocol", &ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}, []string{"h2"}, map[string][]byte{"http/1.1": {}}, false},
		{"protocol without ALPS", &ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}, []string{"http/1.1"}, map[string][]byte{"http/1.1": {}}, false},
		{"no ALPS offered", nil, []string{"h2"}, h2, false},
		{"no ALPN", &ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}, nil, map[string][]byte{"": {}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, server, tickets := eidolonALPSHandshake(t, []string{"h2", "http/1.1"}, tt.alps, tt.serverALPN, tt.serverSettings)
			if tickets != 1 {
				t.Errorf("%d session tickets, want 1", tickets)
			}
			if !tt.want {
				if client.PeerApplicationSettings != nil || server.PeerApplicationSettings != nil {
					t.Errorf("ALPS negotiated: client got %q, server got %q", client.PeerApplicationSettings, server.PeerApplicationSettings)
				}
				return
			}
			if want := tt.serverSettings["h2"]; client.PeerApplicationSettings == nil || !bytes.Equal(client.PeerApplicationSettings, want) {
				t.Errorf("client got %q, want %q", client.PeerApplicationSettings, want)
			}
			if got := server.PeerApplicationSettings; string(got) != "client settings" {
				t.Errorf("server got %q, want the client settings", got)
			}
		})
	}
}

// [eidolon] The ALPS extension of a ClientHello is read with its codepoint
// and protocols, the new codepoint winning when both are present; a
// malformed one fails the ClientHello.
func TestEidolonClientHelloALPS(t *testing.T) {
	ext := func(typ uint16, body ...byte) []byte {
		return append([]byte{byte(typ >> 8), byte(typ), 0, byte(len(body))}, body...)
	}
	list := []byte{0, 6, 2, 'h', '2', 2, 'h', '3'}
	hello := func(exts ...[]byte) []byte {
		body := append([]byte{3, 3}, make([]byte, 32)...)
		body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
		var all []byte
		for _, e := range exts {
			all = append(all, e...)
		}
		body = append(body, byte(len(all)>>8), byte(len(all)))
		body = append(body, all...)
		return append([]byte{typeClientHello, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	}
	for _, tt := range []struct {
		name  string
		msg   []byte
		ok    bool
		code  uint16
		proto []string
	}{
		{"new", hello(ext(17613, list...)), true, 17613, []string{"h2", "h3"}},
		{"old", hello(ext(17513, list...)), true, 17513, []string{"h2", "h3"}},
		{"new then old", hello(ext(17613, list...), ext(17513, 0, 3, 2, 'h', '2')), true, 17613, []string{"h2", "h3"}},
		{"old then new", hello(ext(17513, 0, 3, 2, 'h', '2'), ext(17613, list...)), true, 17613, []string{"h2", "h3"}},
		{"none", hello(), true, 0, nil},
		{"empty list", hello(ext(17613, 0, 0)), false, 0, nil},
		{"empty protocol", hello(ext(17613, 0, 1, 0)), false, 0, nil},
		{"short list", hello(ext(17613, 0, 4, 2, 'h', '2')), false, 0, nil},
		{"trailing byte", hello(ext(17613, append(list, 0)...)), false, 0, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var m clientHelloMsg
			if ok := m.unmarshal(tt.msg); ok != tt.ok {
				t.Fatalf("unmarshal = %v", ok)
			}
			if tt.ok && (m.alpsCodepoint != tt.code || !equalStrings(m.alpsProtocols, tt.proto)) {
				t.Errorf("ALPS %d %q, want %d %q", m.alpsCodepoint, m.alpsProtocols, tt.code, tt.proto)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// [eidolon] With ALPS negotiated, the server requires the client
// EncryptedExtensions with the settings on its codepoint: another message
// is unexpected, and EncryptedExtensions without them or on the other
// codepoint lack an extension.
func TestEidolonServerALPSClientEncryptedExtensions(t *testing.T) {
	for _, tt := range []struct {
		name string
		msg  []byte
		want alert
	}{
		{"settings", []byte{typeEncryptedExtensions, 0, 0, 7, 0, 5, 0x44, 0xcd, 0, 1, 'x'}, 0},
		{"no extension", []byte{typeEncryptedExtensions, 0, 0, 2, 0, 0}, alertMissingExtension},
		{"other codepoint", []byte{typeEncryptedExtensions, 0, 0, 7, 0, 5, 0x44, 0x69, 0, 1, 'x'}, alertMissingExtension},
		{"finished", append([]byte{typeFinished, 0, 0, 32}, make([]byte, 32)...), alertUnexpectedMessage},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, s := net.Pipe()
			defer c.Close()
			srv := Server(s, testConfigServer.Clone())
			srv.vers, srv.haveVers = VersionTLS13, true
			srv.utls.applicationSettingsCodepoint = utlsExtensionApplicationSettingsNew
			hs := &serverHandshakeStateTLS13{c: srv, transcript: sha256.New()}
			go func() {
				// A plaintext record, as no key is set; then the alert.
				c.Write(append([]byte{byte(recordTypeHandshake), 3, 3, 0, byte(len(tt.msg))}, tt.msg...))
				io.Copy(io.Discard, c)
			}()
			err := hs.readClientEncryptedExtensions()
			s.Close()
			if tt.want == 0 {
				if err != nil || string(srv.utls.peerApplicationSettings) != "x" {
					t.Fatalf("err %v, settings %q", err, srv.utls.peerApplicationSettings)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted")
			}
			var op *net.OpError
			if !errors.As(srv.out.err, &op) || op.Err != tt.want {
				t.Errorf("sent %v, want alert %v (error %v)", srv.out.err, tt.want, err)
			}
		})
	}
}
