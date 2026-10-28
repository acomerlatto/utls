package tls

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// [eidolon] The client rejects server extensions it did not offer, GREASE
// values and extensions outside the set BoringSSL accepts in each message
// (RFC 8446, Section 4.2; RFC 8701, Section 3.1). Before the fix, unknown,
// unsolicited and GREASE extensions were silently ignored in ServerHello,
// HelloRetryRequest, EncryptedExtensions and Certificate entries.

// GREASE cases echo the client's own GREASE extension type (see
// eidolonServerScript), the one value that was offered.
const eidolonUnknownExtension uint16 = 0x1234

// eidolonOCSPStatus is a syntactically valid status_request extension of a
// CertificateEntry.
var eidolonOCSPStatus = []byte{statusTypeOCSP, 0, 0, 4, 'o', 'c', 's', 'p'}

// eidolonSCTList is a syntactically valid SCT extension.
var eidolonSCTList = []byte{0, 5, 0, 3, 's', 'c', 't'}

func eidolonECHConfigList(t *testing.T, mutate func(*cryptobyte.Builder)) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(extensionEncryptedClientHello) // version
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(7)       // config_id
			b.AddUint16(0x0020) // DHKEM(X25519, HKDF-SHA256)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, 32)) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(1) })
			b.AddUint8(0) // maximum_name_length
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("example.com")) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {})
			if mutate != nil {
				mutate(b)
			}
		})
	})
	return b.BytesOrPanic()
}

func TestEidolonServerExtensionsTLS13(t *testing.T) {
	ocspStaple := eidolonRawExtension{extensionStatusRequest, eidolonOCSPStatus}
	tests := []struct {
		name      string
		extra     []TLSExtension // offered on top of eidolonTLS13Spec
		script    eidolonServerScript
		wantAlert alert // 0: the handshake completes
	}{
		// ServerHello: only key_share, pre_shared_key and supported_versions.
		{"ServerHello GREASE", []TLSExtension{&UtlsGREASEExtension{}}, eidolonServerScript{
			shExts: []eidolonRawExtension{{GREASE_PLACEHOLDER, nil}}}, alertUnsupportedExtension},
		{"ServerHello unknown", nil, eidolonServerScript{
			shExts: []eidolonRawExtension{{eidolonUnknownExtension, nil}}}, alertUnsupportedExtension},
		{"ServerHello offered server_name", nil, eidolonServerScript{
			shExts: []eidolonRawExtension{{extensionServerName, nil}}}, alertUnsupportedExtension},
		{"ServerHello pre_shared_key not offered", nil, eidolonServerScript{
			shExts: []eidolonRawExtension{eidolonUint16Ext(extensionPreSharedKey, 0)}}, alertUnsupportedExtension},

		// HelloRetryRequest: only cookie, key_share, supported_versions and ECH.
		{"HelloRetryRequest baseline", nil, eidolonServerScript{
			hrrExts: []eidolonRawExtension{}}, 0},
		{"HelloRetryRequest GREASE", []TLSExtension{&UtlsGREASEExtension{}}, eidolonServerScript{
			hrrExts: []eidolonRawExtension{{GREASE_PLACEHOLDER, nil}}}, alertUnsupportedExtension},
		{"HelloRetryRequest unknown", nil, eidolonServerScript{
			hrrExts: []eidolonRawExtension{{eidolonUnknownExtension, nil}}}, alertUnsupportedExtension},
		{"HelloRetryRequest offered server_name", nil, eidolonServerScript{
			hrrExts: []eidolonRawExtension{{extensionServerName, nil}}}, alertUnsupportedExtension},

		// EncryptedExtensions: only offered extensions.
		{"EncryptedExtensions server_name", nil, eidolonServerScript{
			eeExts: []eidolonRawExtension{{extensionServerName, nil}}}, 0},
		{"EncryptedExtensions GREASE", []TLSExtension{&UtlsGREASEExtension{}}, eidolonServerScript{
			eeExts: []eidolonRawExtension{{GREASE_PLACEHOLDER, nil}}}, alertUnsupportedExtension},
		{"EncryptedExtensions unknown", nil, eidolonServerScript{
			eeExts: []eidolonRawExtension{{eidolonUnknownExtension, nil}}}, alertUnsupportedExtension},
		{"EncryptedExtensions ALPN not offered", nil, eidolonServerScript{
			alpn: "h2"}, alertUnsupportedExtension},
		{"EncryptedExtensions offered status_request", []TLSExtension{&StatusRequestExtension{}}, eidolonServerScript{
			eeExts: []eidolonRawExtension{{extensionStatusRequest, nil}}}, alertDecodeError},
		{"EncryptedExtensions ECH not offered", nil, eidolonServerScript{
			eeExts: []eidolonRawExtension{{extensionEncryptedClientHello, eidolonECHConfigList(t, nil)}}}, alertUnsupportedExtension},
		{"EncryptedExtensions GREASE ECH, valid retry_configs", []TLSExtension{BoringGREASEECH()}, eidolonServerScript{
			eeExts: []eidolonRawExtension{{extensionEncryptedClientHello, eidolonECHConfigList(t, nil)}}}, 0},
		{"EncryptedExtensions GREASE ECH, malformed retry_configs", []TLSExtension{BoringGREASEECH()}, eidolonServerScript{
			eeExts: []eidolonRawExtension{{extensionEncryptedClientHello, []byte{0, 1, 0}}}}, alertDecodeError},

		// Certificate entries: only status_request and SCT, if offered.
		{"Certificate offered status_request", []TLSExtension{&StatusRequestExtension{}}, eidolonServerScript{
			certExts: []eidolonRawExtension{ocspStaple}}, 0},
		{"Certificate status_request not offered", nil, eidolonServerScript{
			certExts: []eidolonRawExtension{ocspStaple}}, alertUnsupportedExtension},
		{"Certificate GREASE", []TLSExtension{&UtlsGREASEExtension{}}, eidolonServerScript{
			certExts: []eidolonRawExtension{{GREASE_PLACEHOLDER, nil}}}, alertUnsupportedExtension},
		{"Certificate unknown", nil, eidolonServerScript{
			certExts: []eidolonRawExtension{{eidolonUnknownExtension, nil}}}, alertUnsupportedExtension},
		{"Certificate offered server_name", nil, eidolonServerScript{
			certExts: []eidolonRawExtension{{extensionServerName, nil}}}, alertUnsupportedExtension},
		{"Certificate duplicate SCT", []TLSExtension{&SCTExtension{}}, eidolonServerScript{
			certExts: []eidolonRawExtension{{extensionSCT, eidolonSCTList}, {extensionSCT, eidolonSCTList}}}, alertIllegalParameter},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, cerr, serr := eidolonScriptedConn(t, eidolonTLS13Spec(tt.extra...), nil, tt.script)
			if tt.wantAlert != 0 {
				eidolonExpectAlert(t, cerr, serr, tt.wantAlert)
				return
			}
			eidolonExpectSuccess(t, cerr, serr)
			if len(tt.script.certExts) > 0 && !bytes.Equal(u.ConnectionState().OCSPResponse, eidolonOCSPStatus[4:]) {
				t.Errorf("OCSPResponse = %x, want %x", u.ConnectionState().OCSPResponse, eidolonOCSPStatus[4:])
			}
		})
	}
}

func TestEidolonServerExtensionsTLS12(t *testing.T) {
	spec := func(scsv bool, extra ...TLSExtension) *ClientHelloSpec {
		exts := append([]TLSExtension{
			&SNIExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{X25519}},
			&SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{ECDSAWithP256AndSHA256}},
			&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13, VersionTLS12}},
		}, extra...)
		suites := []uint16{TLS_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
		if scsv {
			suites = append(suites, scsvRenegotiation)
		}
		return &ClientHelloSpec{
			TLSVersMin:         VersionTLS12,
			TLSVersMax:         VersionTLS13,
			CipherSuites:       suites,
			CompressionMethods: []uint8{compressionNone},
			Extensions:         exts,
		}
	}
	renegotiationInfo := eidolonRawExtension{extensionRenegotiationInfo, []byte{0}}
	tests := []struct {
		name      string
		scsv      bool
		extra     []TLSExtension
		shExts    []eidolonRawExtension
		wantAlert alert // 0: the client accepts the ServerHello
	}{
		{"GREASE", false, []TLSExtension{&UtlsGREASEExtension{}}, []eidolonRawExtension{{GREASE_PLACEHOLDER, nil}}, alertUnsupportedExtension},
		{"unknown", false, nil, []eidolonRawExtension{{eidolonUnknownExtension, nil}}, alertUnsupportedExtension},
		{"session_ticket not offered", false, nil, []eidolonRawExtension{{extensionSessionTicket, nil}}, alertUnsupportedExtension},
		{"offered key_share", false, nil, []eidolonRawExtension{{extensionKeyShare, []byte{0, 0x1d, 0, 0}}}, alertUnsupportedExtension},
		{"renegotiation_info not offered", false, nil, []eidolonRawExtension{renegotiationInfo}, alertUnsupportedExtension},
		// RFC 5746, Section 3.4: the server answers the SCSV with the extension.
		{"renegotiation_info answering the SCSV", true, nil, []eidolonRawExtension{renegotiationInfo}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cerr, serr := eidolonScriptedHandshake(t, spec(tt.scsv, tt.extra...), nil, eidolonServerScript{
				tls12:  true,
				shExts: append([]eidolonRawExtension{{extensionSupportedPoints, []byte{1, pointFormatUncompressed}}}, tt.shExts...),
			})
			if tt.wantAlert != 0 {
				eidolonExpectAlert(t, cerr, serr, tt.wantAlert)
				return
			}
			// The scripted server stops after the ServerHello: a client that
			// accepted it was still waiting for the Certificate.
			if serr == nil || !strings.Contains(serr.Error(), "did not abort") {
				t.Fatalf("client rejected the ServerHello: client: %v; server: %v", cerr, serr)
			}
		})
	}
}

// The ECHConfigList syntax check matches BoringSSL ssl_is_valid_ech_config_list.
func TestEidolonValidECHConfigList(t *testing.T) {
	valid := eidolonECHConfigList(t, nil)
	if !isValidECHConfigList(valid) {
		t.Fatal("rejected a valid ECHConfigList")
	}
	unknownVersion := []byte{0, 6, 0xfe, 0x0c, 0, 2, 0xaa, 0xbb}
	if !isValidECHConfigList(unknownVersion) {
		t.Error("rejected an ECHConfig of an unknown version, which is skipped")
	}
	for name, b := range map[string][]byte{
		"empty":            {},
		"empty list":       {0, 0},
		"trailing data":    append(bytes.Clone(valid), 0),
		"truncated":        valid[:len(valid)-1],
		"config trailing":  eidolonECHConfigList(t, func(b *cryptobyte.Builder) { b.AddUint8(0) }),
		"bad length field": append([]byte{0, byte(len(valid))}, valid[2:]...),
	} {
		if isValidECHConfigList(b) {
			t.Errorf("%s: accepted an invalid ECHConfigList", name)
		}
	}
}
