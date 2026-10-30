package tls

import (
	"net"
	"testing"
)

// [eidolon] With PreferSkipResumptionOnNilExtension, a TLS 1.2 session
// and a spec with pre_shared_key but without session_ticket make a full
// handshake; uTLS skipped the ticket, then asserted it had been set and
// panicked.
func TestEidolonSkipTLS12SessionWithoutTicketExtension(t *testing.T) {
	cache := NewLRUClientSessionCache(1)
	cert, _ := eidolonSelfSigned(t, "example.com")
	serverConfig := &Config{Certificates: []Certificate{cert}, MaxVersion: VersionTLS12}
	handshake := func(t *testing.T, client func(net.Conn) *UConn) *UConn {
		c, s := localPipe(t)
		done := make(chan error, 1)
		go func() {
			defer s.Close()
			done <- Server(s, serverConfig).Handshake()
		}()
		uc := client(c)
		defer c.Close()
		if err := uc.Handshake(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		return uc
	}
	config := &Config{ServerName: "example.com", InsecureSkipVerify: true, ClientSessionCache: cache, PreferSkipResumptionOnNilExtension: true, OmitEmptyPsk: true}
	handshake(t, func(c net.Conn) *UConn { return UClient(c, config.Clone(), HelloChrome_120) })

	uc := handshake(t, func(c net.Conn) *UConn {
		spec, err := UTLSIdToSpec(HelloChrome_120)
		if err != nil {
			t.Fatal(err)
		}
		var exts []TLSExtension
		for _, e := range spec.Extensions {
			if _, ok := e.(*SessionTicketExtension); !ok {
				exts = append(exts, e)
			}
		}
		spec.Extensions = append(exts, &UtlsPreSharedKeyExtension{})
		uc := UClient(c, config.Clone(), HelloCustom)
		if err := uc.ApplyPreset(&spec); err != nil {
			t.Fatal(err)
		}
		return uc
	})
	if uc.ConnectionState().DidResume {
		t.Error("resumed without the session_ticket extension")
	}
}
