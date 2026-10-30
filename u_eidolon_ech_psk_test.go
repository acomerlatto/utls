package tls

import (
	"testing"
)

// eidolonPSKSpec returns the Chrome spec with pre_shared_key last, and
// with only suites as its cipher suites when given.
func eidolonPSKSpec(t *testing.T, suites ...uint16) *ClientHelloSpec {
	t.Helper()
	spec, err := utlsIdToSpec(HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	spec.Extensions = append(spec.Extensions, &UtlsPreSharedKeyExtension{})
	if len(suites) > 0 {
		spec.CipherSuites = suites
	}
	return &spec
}

// eidolonResume is one handshake of client with spec against server: it
// returns the client, its error, the ClientHellos it wrote and the
// extensions of the ClientHelloInner the server read first. After the
// handshake, the client reads one byte, which brings the TLS 1.3 tickets.
func eidolonResume(t *testing.T, spec *ClientHelloSpec, client, server *Config) (u *UConn, err error, outers []*clientHelloMsg, innerExts []uint16) {
	t.Helper()
	// The clones share the ticket keys only when they are set.
	server.SetSessionTicketKeys([][32]byte{{1}})
	server = server.Clone()
	server.GetConfigForClient = func(chi *ClientHelloInfo) (*Config, error) {
		innerExts = chi.Extensions
		return nil, nil
	}
	c, s := localPipe(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer s.Close()
		if srv := Server(s, server); srv.Handshake() == nil {
			srv.Write([]byte{1})
		}
	}()
	rec := &eidolonWriteRecorder{Conn: c}
	u = UClient(rec, client, HelloCustom)
	if err := u.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err = u.Handshake(); err == nil {
		_, err = u.Read(make([]byte, 1))
	}
	c.Close()
	<-done
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return u, err, eidolonClientHellos(t, rec.written), innerExts
}

// eidolonClientHellos returns the ClientHellos in the plaintext handshake
// records of raw.
func eidolonClientHellos(t *testing.T, raw []byte) []*clientHelloMsg {
	t.Helper()
	var handshake []byte
	for len(raw) >= 5 && recordType(raw[0]) != recordTypeApplicationData {
		n := int(raw[3])<<8 | int(raw[4])
		if recordType(raw[0]) == recordTypeHandshake {
			handshake = append(handshake, raw[5:5+n]...)
		}
		raw = raw[5+n:]
	}
	var hellos []*clientHelloMsg
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
			hellos = append(hellos, m)
		}
		handshake = handshake[n:]
	}
	return hellos
}

// [eidolon] With ECH, a TLS 1.2 session is not offered, as BoringSSL does
// not offer it (ssl_handshake_client.cc, do_start_connect): its ticket in
// ClientHelloOuter would be seen by everyone.
func TestEidolonECHNoTLS12Session(t *testing.T) {
	client, server := eidolonECHServer(t)
	client.ClientSessionCache = NewLRUClientSessionCache(1)
	client.OmitEmptyPsk = true
	tls12 := server.Clone()
	tls12.MinVersion, tls12.MaxVersion = VersionTLS12, VersionTLS12
	tls12.EncryptedClientHelloKeys = nil
	plain := client.Clone()
	plain.EncryptedClientHelloConfigList = nil
	if _, err, _, _ := eidolonResume(t, eidolonPSKSpec(t), plain, tls12); err != nil {
		t.Fatal(err)
	}
	if cs, _ := client.ClientSessionCache.Get("secret.example"); cs == nil || cs.session.version != VersionTLS12 {
		t.Fatal("no TLS 1.2 session in cache")
	}
	u, err, outers, _ := eidolonResume(t, eidolonPSKSpec(t), client, server)
	if err != nil {
		t.Fatal(err)
	}
	if st := u.ConnectionState(); st.DidResume || !st.ECHAccepted {
		t.Fatalf("resumed %v, ECH accepted %v; want a full handshake with ECH", st.DidResume, st.ECHAccepted)
	}
	for i, outer := range outers {
		if len(outer.sessionTicket) > 0 {
			t.Errorf("ClientHelloOuter %d carries the TLS 1.2 ticket", i)
		}
	}
}
