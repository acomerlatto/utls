package tls

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"

	"github.com/acomerlatto/utls/internal/tls13"
)

// [eidolon] A scripted TLS server for regression tests that need server
// messages the Go server never sends: arbitrary extensions in ServerHello,
// HelloRetryRequest, EncryptedExtensions and Certificate, or a
// CertificateVerify algorithm the client did not offer. Apart from what the
// script changes, it runs a valid TLS 1.3 handshake with X25519 and
// TLS_AES_128_GCM_SHA256, so a client that ignores the change completes it.

type eidolonRawExtension struct {
	typ  uint16
	data []byte
}

// An extension of type GREASE_PLACEHOLDER in a script is sent with the type
// of the client's GREASE extension, as if the server echoed it.

type eidolonServerScript struct {
	// tls12 sends a TLS 1.2 ServerHello carrying shExts and then only waits
	// for the client's reaction.
	tls12 bool
	// tls12Version replaces TLS 1.2 in the ServerHello of tls12.
	tls12Version uint16
	// hrrExts, when not nil, makes the server send a HelloRetryRequest with
	// supported_versions, a cookie and these extensions.
	hrrExts  []eidolonRawExtension
	shExts   []eidolonRawExtension
	alpn     string
	eeExts   []eidolonRawExtension
	certExts []eidolonRawExtension // extensions of the leaf certificate entry
	cert     *Certificate          // default testECDSAP256Cert
	sigAlg   SignatureScheme       // default ECDSAWithP256AndSHA256
}

// eidolonRawMessage is a handshake message already marshaled by the script.
type eidolonRawMessage []byte

func (m eidolonRawMessage) marshal() ([]byte, error) { return m, nil }
func (m eidolonRawMessage) unmarshal([]byte) bool    { return false }

func eidolonAddExtensions(b *cryptobyte.Builder, exts []eidolonRawExtension) {
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, e := range exts {
			b.AddUint16(e.typ)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(e.data)
			})
		}
	})
}

func eidolonServerHelloBytes(vers uint16, random, sessionID []byte, suite uint16, exts []eidolonRawExtension) []byte {
	var b cryptobyte.Builder
	b.AddUint8(typeServerHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(vers)
		b.AddBytes(random)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(sessionID)
		})
		b.AddUint16(suite)
		b.AddUint8(compressionNone)
		eidolonAddExtensions(b, exts)
	})
	return b.BytesOrPanic()
}

func eidolonUint16Ext(typ, v uint16) eidolonRawExtension {
	return eidolonRawExtension{typ, []byte{byte(v >> 8), byte(v)}}
}

// eidolonPeerAlert returns the alert the peer sent, if err carries one.
func eidolonPeerAlert(err error) (alert, bool) {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "remote error" {
		a, ok := opErr.Err.(alert)
		return a, ok
	}
	return 0, false
}

func eidolonRunScriptedServer(conn net.Conn, s eidolonServerScript) error {
	c := &Conn{conn: conn, config: testConfigServer.Clone()}

	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	ch, ok := msg.(*clientHelloMsg)
	if !ok {
		return fmt.Errorf("scripted server: got %T, want ClientHello", msg)
	}

	random := make([]byte, 32)
	rand.Read(random)

	echoGREASE := func(exts []eidolonRawExtension) []eidolonRawExtension {
		out := slices.Clone(exts)
		for i := range out {
			if out[i].typ != GREASE_PLACEHOLDER {
				continue
			}
			for _, typ := range ch.extensions {
				if isGREASEUint16(typ) {
					out[i].typ = typ
				}
			}
		}
		return out
	}
	s.hrrExts = echoGREASE(s.hrrExts)
	s.shExts = echoGREASE(s.shExts)
	s.eeExts = echoGREASE(s.eeExts)
	s.certExts = echoGREASE(s.certExts)

	if s.tls12 {
		c.vers, c.haveVers = VersionTLS12, true
		if s.tls12Version != 0 {
			c.vers = s.tls12Version
		}
		c.in.version, c.out.version = c.vers, c.vers
		// A TLS 1.2 server does not echo the TLS 1.3 compatibility session ID.
		sh := eidolonServerHelloBytes(c.vers, random, nil,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, s.shExts)
		if _, err := c.writeHandshakeRecord(eidolonRawMessage(sh), nil); err != nil {
			return err
		}
		// A client that accepts the ServerHello waits for the Certificate.
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err := c.readHandshake(nil)
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			err = errors.New("scripted server: client did not abort after the TLS 1.2 ServerHello")
		}
		return err
	}

	c.vers, c.haveVers = VersionTLS13, true
	c.in.version, c.out.version = c.vers, c.vers
	suite := cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)
	transcript := suite.hash.New()
	if err := transcriptMsg(ch, transcript); err != nil {
		return err
	}

	if s.hrrExts != nil {
		exts := append([]eidolonRawExtension{
			eidolonUint16Ext(extensionSupportedVersions, VersionTLS13),
			{extensionCookie, []byte{0, 7, 'e', 'i', 'd', 'o', 'l', 'o', 'n'}},
		}, s.hrrExts...)
		hrr := eidolonServerHelloBytes(VersionTLS12, helloRetryRequestRandom, ch.sessionId, suite.id, exts)
		chHash := transcript.Sum(nil)
		transcript.Reset()
		transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
		transcript.Write(chHash)
		if _, err := c.writeHandshakeRecord(eidolonRawMessage(hrr), transcript); err != nil {
			return err
		}
		if msg, err = c.readHandshake(transcript); err != nil {
			return err
		}
		if ch, ok = msg.(*clientHelloMsg); !ok {
			return fmt.Errorf("scripted server: got %T, want second ClientHello", msg)
		}
	}

	var clientShare []byte
	for _, ks := range ch.keyShares {
		if ks.group == X25519 {
			clientShare = ks.data
		}
	}
	if clientShare == nil {
		return errors.New("scripted server: client sent no X25519 key share")
	}
	ke, err := keyExchangeForCurveID(X25519)
	if err != nil {
		return err
	}
	sharedKey, serverShare, err := ke.serverSharedSecret(rand.Reader, clientShare)
	if err != nil {
		return err
	}
	var ks cryptobyte.Builder
	ks.AddUint16(uint16(X25519))
	ks.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(serverShare.data) })
	shExts := append([]eidolonRawExtension{
		eidolonUint16Ext(extensionSupportedVersions, VersionTLS13),
		{extensionKeyShare, ks.BytesOrPanic()},
	}, s.shExts...)
	sh := eidolonServerHelloBytes(VersionTLS12, random, ch.sessionId, suite.id, shExts)
	if _, err := c.writeHandshakeRecord(eidolonRawMessage(sh), transcript); err != nil {
		return err
	}

	handshakeSecret := tls13.NewEarlySecret(suite.hash.New, nil).HandshakeSecret(sharedKey)
	c.setWriteTrafficSecret(suite, QUICEncryptionLevelHandshake,
		handshakeSecret.ServerHandshakeTrafficSecret(transcript))
	// The read key is set once the client answered: a client that rejects the
	// ServerHello sends its alert in plaintext.
	clientSecret := handshakeSecret.ClientHandshakeTrafficSecret(transcript)

	var ee cryptobyte.Builder
	ee.AddUint8(typeEncryptedExtensions)
	ee.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		exts := s.eeExts
		if s.alpn != "" {
			var alpn cryptobyte.Builder
			alpn.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(s.alpn)) })
			})
			exts = append([]eidolonRawExtension{{extensionALPN, alpn.BytesOrPanic()}}, exts...)
		}
		eidolonAddExtensions(b, exts)
	})
	if _, err := c.writeHandshakeRecord(eidolonRawMessage(ee.BytesOrPanic()), transcript); err != nil {
		return err
	}

	cert := s.cert
	if cert == nil {
		cert = &testECDSAP256Cert
	}
	var cm cryptobyte.Builder
	cm.AddUint8(typeCertificate)
	cm.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0) // certificate_request_context
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			for i, der := range cert.Certificate {
				b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(der) })
				if i == 0 {
					eidolonAddExtensions(b, s.certExts)
				} else {
					eidolonAddExtensions(b, nil)
				}
			}
		})
	})
	if _, err := c.writeHandshakeRecord(eidolonRawMessage(cm.BytesOrPanic()), transcript); err != nil {
		return err
	}

	sigAlg := s.sigAlg
	if sigAlg == 0 {
		sigAlg = ECDSAWithP256AndSHA256
	}
	sigType, sigHash, err := typeAndHashFromSignatureScheme(sigAlg)
	if err != nil {
		return err
	}
	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	sig, err := crypto.SignMessage(cert.PrivateKey.(crypto.Signer), rand.Reader,
		signedMessage(serverSignatureContext, transcript), signOpts)
	if err != nil {
		return err
	}
	cv := &certificateVerifyMsg{hasSignatureAlgorithm: true, signatureAlgorithm: sigAlg, signature: sig}
	if _, err := c.writeHandshakeRecord(cv, transcript); err != nil {
		return err
	}

	fin := &finishedMsg{verifyData: suite.finishedHash(c.out.trafficSecret, transcript)}
	if _, err := c.writeHandshakeRecord(fin, transcript); err != nil {
		return err
	}

	if err := eidolonSkipPlaintextRecords(c); err != nil {
		return err
	}
	if err := c.setReadTrafficSecret(suite, QUICEncryptionLevelHandshake, clientSecret, false); err != nil {
		return err
	}

	// Read the client's flight up to its Finished; a client EncryptedExtensions
	// (ALPS) may come first.
	for {
		msg, err := c.readHandshake(nil)
		if err != nil {
			return err
		}
		if _, ok := msg.(*finishedMsg); ok {
			return nil
		}
	}
}

// eidolonSkipPlaintextRecords reads the client's plaintext records before its
// encrypted flight: it skips the compatibility ChangeCipherSpec and returns
// a plaintext alert as an error. The first other record is pushed back.
func eidolonSkipPlaintextRecords(c *Conn) error {
	for {
		hdr := make([]byte, recordHeaderLen)
		if _, err := io.ReadFull(c.conn, hdr); err != nil {
			return err
		}
		body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
		if _, err := io.ReadFull(c.conn, body); err != nil {
			return err
		}
		switch recordType(hdr[0]) {
		case recordTypeChangeCipherSpec:
			continue
		case recordTypeAlert:
			if len(body) == 2 {
				return &net.OpError{Op: "remote error", Err: alert(body[1])}
			}
		}
		c.conn = &eidolonPrefixConn{Conn: c.conn, r: io.MultiReader(bytes.NewReader(append(hdr, body...)), c.conn)}
		return nil
	}
}

type eidolonPrefixConn struct {
	net.Conn
	r io.Reader
}

func (c *eidolonPrefixConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// eidolonScriptedHandshake runs a UConn built from spec against the scripted
// server and returns the client error and the server error. The client side
// stays open until the server returns, so the server reads the alert the
// client sent.
func eidolonScriptedHandshake(t *testing.T, spec *ClientHelloSpec, config *Config, s eidolonServerScript) (clientErr, serverErr error) {
	t.Helper()
	_, clientErr, serverErr = eidolonScriptedConn(t, spec, config, s)
	return clientErr, serverErr
}

func eidolonScriptedConn(t *testing.T, spec *ClientHelloSpec, config *Config, s eidolonServerScript) (u *UConn, clientErr, serverErr error) {
	t.Helper()
	c, srv := localPipe(t)
	defer c.Close()
	defer srv.Close()
	deadline := time.Now().Add(10 * time.Second)
	c.SetDeadline(deadline)
	srv.SetDeadline(deadline)

	errc := make(chan error, 1)
	go func() {
		err := eidolonRunScriptedServer(srv, s)
		srv.Close()
		errc <- err
	}()

	if config == nil {
		config = testConfigClient.Clone()
	}
	u = UClient(c, config, HelloCustom)
	if err := u.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	clientErr = u.Handshake()
	return u, clientErr, <-errc
}

// eidolonTLS13Spec is a minimal TLS 1.3 spec the scripted server accepts.
// extra extensions are inserted before supported_versions.
func eidolonTLS13Spec(extra ...TLSExtension) *ClientHelloSpec {
	exts := []TLSExtension{
		&SNIExtension{},
		&SupportedCurvesExtension{Curves: []CurveID{X25519}},
		&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
			ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256,
		}},
		&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
	}
	exts = append(exts, extra...)
	exts = append(exts, &SupportedVersionsExtension{Versions: []uint16{VersionTLS13}})
	return &ClientHelloSpec{
		TLSVersMin:         VersionTLS13,
		TLSVersMax:         VersionTLS13,
		CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		CompressionMethods: []uint8{compressionNone},
		Extensions:         exts,
	}
}

// eidolonExpectAlert checks that the client aborted and sent want.
func eidolonExpectAlert(t *testing.T, clientErr, serverErr error, want alert) {
	t.Helper()
	if clientErr == nil {
		t.Fatalf("client completed the handshake, want it to abort with %v", want)
	}
	got, ok := eidolonPeerAlert(serverErr)
	if !ok {
		t.Fatalf("client error %q; server did not receive an alert (server error: %v), want %v", clientErr, serverErr, want)
	}
	if got != want {
		t.Fatalf("client sent alert %q (client error %q), want %q", got, clientErr, want)
	}
}

// eidolonExpectSuccess checks that both sides completed the handshake.
func eidolonExpectSuccess(t *testing.T, clientErr, serverErr error) {
	t.Helper()
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake failed: client: %v; server: %v", clientErr, serverErr)
	}
}

// A sanity check of the scripted server itself.
func TestEidolonScriptedServerBaseline(t *testing.T) {
	cerr, serr := eidolonScriptedHandshake(t, eidolonTLS13Spec(), nil, eidolonServerScript{})
	eidolonExpectSuccess(t, cerr, serr)
	cerr, serr = eidolonScriptedHandshake(t, eidolonTLS13Spec(), nil, eidolonServerScript{hrrExts: []eidolonRawExtension{}})
	eidolonExpectSuccess(t, cerr, serr)
}
