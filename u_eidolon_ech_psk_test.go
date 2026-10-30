package tls

import (
	"bytes"
	"errors"
	"slices"
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

// eidolonTicket returns the ticket of the session in cache.
func eidolonTicket(t *testing.T, cache ClientSessionCache) []byte {
	t.Helper()
	cs, _ := cache.Get("secret.example")
	if cs == nil {
		t.Fatal("no session in cache")
	}
	return cs.session.ticket
}

// eidolonNoOuterPSK fails t if a ClientHelloOuter offers a PSK or carries
// ticket.
func eidolonNoOuterPSK(t *testing.T, outers []*clientHelloMsg, ticket []byte) {
	t.Helper()
	for i, outer := range outers {
		raw, err := outer.marshal()
		if err != nil {
			t.Fatal(err)
		}
		if len(outer.pskIdentities) > 0 || bytes.Contains(raw, ticket) {
			t.Errorf("ClientHelloOuter %d offers the session", i)
		}
	}
}

// [eidolon] With ECH, the session is resumed as BoringSSL resumes it: the
// PSK goes last in ClientHelloInner, with its binder over the inner
// transcript, and ClientHelloOuter offers none (should_offer_psk), also
// after a HelloRetryRequest. uTLS refused a PSK with a custom ECH
// ClientHello.
func TestEidolonECHResumption(t *testing.T) {
	for _, hrr := range []bool{false, true} {
		t.Run(map[bool]string{false: "ServerHello", true: "HelloRetryRequest"}[hrr], func(t *testing.T) {
			client, server := eidolonECHServer(t)
			client.ClientSessionCache = NewLRUClientSessionCache(1)
			client.OmitEmptyPsk = true
			if _, err, _, _ := eidolonResume(t, eidolonPSKSpec(t), client, server); err != nil {
				t.Fatal(err)
			}
			ticket := eidolonTicket(t, client.ClientSessionCache)
			if hrr {
				server.CurvePreferences = []CurveID{CurveP384}
			}
			u, err, outers, innerExts := eidolonResume(t, eidolonPSKSpec(t), client, server)
			if err != nil {
				t.Fatal(err)
			}
			st := u.ConnectionState()
			if !st.DidResume || !st.ECHAccepted || st.HelloRetryRequest != hrr {
				t.Fatalf("resumed %v, ECH accepted %v, HRR %v; want a resumption with ECH, HRR %v", st.DidResume, st.ECHAccepted, st.HelloRetryRequest, hrr)
			}
			if len(innerExts) == 0 || innerExts[len(innerExts)-1] != extensionPreSharedKey {
				t.Errorf("ClientHelloInner extensions %v, want pre_shared_key last", innerExts)
			}
			eidolonNoOuterPSK(t, outers, ticket)
		})
	}
}

// [eidolon] After a HelloRetryRequest for a cipher suite whose hash is not
// the session's, the second ClientHelloInner leaves the PSK out, as
// BoringSSL drops it (pre_shared_keys.EraseIf in do_read_hello_retry_request).
func TestEidolonECHResumptionHashMismatch(t *testing.T) {
	client, server := eidolonECHServer(t)
	client.ClientSessionCache = NewLRUClientSessionCache(1)
	client.OmitEmptyPsk = true
	if _, err, _, _ := eidolonResume(t, eidolonPSKSpec(t, TLS_AES_256_GCM_SHA384), client, server); err != nil {
		t.Fatal(err)
	}
	server.CurvePreferences = []CurveID{CurveP384}
	u, err, _, _ := eidolonResume(t, eidolonPSKSpec(t, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384), client, server)
	if err != nil {
		t.Fatal(err)
	}
	if st := u.ConnectionState(); st.DidResume || !st.ECHAccepted || !st.HelloRetryRequest {
		t.Fatalf("resumed %v, ECH accepted %v, HRR %v; want a full handshake with ECH after HRR", st.DidResume, st.ECHAccepted, st.HelloRetryRequest)
	}
	if inner := u.echCtx.innerHello; len(inner.pskIdentities) != 0 {
		t.Error("the second ClientHelloInner offers the session")
	}
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

// [eidolon] When a HelloRetryRequest rejects ECH, the second
// ClientHelloOuter offers no PSK either, and the handshake ends in the ECH
// rejection.
func TestEidolonECHRejectedResumption(t *testing.T) {
	client, server := eidolonECHServer(t)
	client.ClientSessionCache = NewLRUClientSessionCache(1)
	client.OmitEmptyPsk = true
	if _, err, _, _ := eidolonResume(t, eidolonPSKSpec(t), client, server); err != nil {
		t.Fatal(err)
	}
	ticket := eidolonTicket(t, client.ClientSessionCache)
	other, _ := eidolonECHServer(t)
	client.EncryptedClientHelloConfigList = other.EncryptedClientHelloConfigList
	server.CurvePreferences = []CurveID{CurveP384}
	u, err, outers, _ := eidolonResume(t, eidolonPSKSpec(t), client, server)
	var rej *ECHRejectionError
	if !errors.As(err, &rej) || !u.ConnectionState().HelloRetryRequest {
		t.Fatalf("handshake error %v, HRR %v; want an ECH rejection after HRR", err, u.ConnectionState().HelloRetryRequest)
	}
	if len(outers) != 2 {
		t.Fatalf("%d ClientHellos, want 2", len(outers))
	}
	eidolonNoOuterPSK(t, outers, ticket)
	if slices.ContainsFunc(outers, func(m *clientHelloMsg) bool { return len(m.pskBinders) > 0 }) {
		t.Error("a ClientHelloOuter has PSK binders")
	}
}

// [eidolon] A FakePreSharedKeyExtension cannot be bound to
// ClientHelloInner, so it is refused with ECH.
func TestEidolonECHFakePSK(t *testing.T) {
	client, _ := eidolonECHServer(t)
	spec := eidolonPSKSpec(t)
	spec.Extensions[len(spec.Extensions)-1] = &FakePreSharedKeyExtension{
		Identities: []PskIdentity{{Label: []byte("fake")}},
		Binders:    [][]byte{make([]byte, 32)},
	}
	u := UClient(nil, client, HelloCustom)
	if err := u.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err := u.BuildHandshakeState(); err == nil {
		t.Error("a FakePreSharedKeyExtension was accepted with ECH")
	}
}

// [eidolon] A spec without extensions has no encrypted_client_hello to
// carry ECH: an error, not a panic.
func TestEidolonECHNoExtensions(t *testing.T) {
	client, _ := eidolonECHServer(t)
	u := UClient(nil, client, HelloCustom)
	if err := u.ApplyPreset(&ClientHelloSpec{CipherSuites: []uint16{TLS_AES_128_GCM_SHA256}}); err != nil {
		t.Fatal(err)
	}
	if err := u.BuildHandshakeState(); err == nil {
		t.Error("a spec without extensions was accepted with ECH")
	}
}
