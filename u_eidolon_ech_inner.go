// [eidolon] ClientHelloInner with the shape of BoringSSL.

package tls

import (
	"errors"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

// echInnerOmitted holds the extensions of ClientHelloOuter that BoringSSL
// leaves out of ClientHelloInner: those of TLS 1.2 and below, the padding
// of the outer and the PSK, which ClientHelloOuter does not offer.
var echInnerOmitted = map[uint16]bool{
	extensionExtendedMasterSecret: true,
	extensionRenegotiationInfo:    true,
	extensionSessionTicket:        true,
	extensionSupportedPoints:      true,
	extensionNextProtoNeg:         true,
	fakeExtensionChannelID:        true,
	utlsExtensionPadding:          true,
	extensionPreSharedKey:         true,
}

// echInnerCompressed holds the extensions BoringSSL writes as compressible
// (out_compressible in ssl/extensions.cc): ClientHelloInner has them as in
// ClientHelloOuter, and EncodedClientHelloInner names them in
// ech_outer_extensions. GREASE extensions are compressed too.
var echInnerCompressed = map[uint16]bool{
	extensionSupportedCurves:            true,
	extensionALPN:                       true,
	extensionStatusRequest:              true,
	extensionSignatureAlgorithms:        true,
	extensionSCT:                        true,
	extensionKeyShare:                   true,
	extensionPSKModes:                   true,
	extensionEarlyData:                  true,
	extensionCookie:                     true,
	utlsExtensionCompressCertificate:    true,
	utlsExtensionApplicationSettings:    true,
	utlsExtensionApplicationSettingsNew: true,
	extensionCertificateAuthorities:     true,
	utlsExtensionTrustAnchors:           true,
}

// echInner builds ClientHelloInner from outer, the marshaled
// ClientHelloOuter with its handshake header, as BoringSSL does
// (ssl_encrypt_client_hello, ssl_add_clienthello_tlsext_inner). It returns
// ClientHelloInner with its header, for the transcript, and
// EncodedClientHelloInner padded as RFC 9849, Section 6.1.3 says.
//
// ClientHelloInner has random, the session ID of the outer, its GREASE and
// TLS 1.3 cipher suites, and its extensions in order with three changes:
// server_name has serverName (none when empty), encrypted_client_hello is
// of type inner and supported_versions keeps GREASE and TLS 1.3. The
// extensions of echInnerOmitted are left out, and those of
// echInnerCompressed and GREASE go after the others, in their order,
// replaced by ech_outer_extensions in EncodedClientHelloInner. Other
// extensions are copied. A non-nil psk goes last in both, uncompressed,
// with its binder over ClientHelloInner.
func echInner(outer, random []byte, serverName string, maxNameLength int, psk *UtlsPreSharedKeyExtension) (inner, encoded []byte, err error) {
	errMalformed := errors.New("tls: malformed ClientHelloOuter")
	s := cryptobyte.String(outer)
	var sessionID, suites, compression, exts cryptobyte.String
	var msgType uint8
	var body cryptobyte.String
	if !s.ReadUint8(&msgType) || msgType != typeClientHello ||
		!s.ReadUint24LengthPrefixed(&body) || !s.Empty() ||
		!body.Skip(2+32) ||
		!body.ReadUint8LengthPrefixed(&sessionID) ||
		!body.ReadUint16LengthPrefixed(&suites) ||
		!body.ReadUint8LengthPrefixed(&compression) ||
		!body.ReadUint16LengthPrefixed(&exts) || !body.Empty() {
		return nil, nil, errMalformed
	}

	var innerSuites []uint16
	for !suites.Empty() {
		var id uint16
		if !suites.ReadUint16(&id) {
			return nil, nil, errMalformed
		}
		if isGREASEUint16(id) || cipherSuiteTLS13ByID(id) != nil {
			innerSuites = append(innerSuites, id)
		}
	}

	var plain, compressed cryptobyte.Builder
	var compressedTypes []uint16
	for !exts.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&typ) || !exts.ReadUint16LengthPrefixed(&data) {
			return nil, nil, errMalformed
		}
		switch {
		case echInnerOmitted[typ]:
		case typ == extensionServerName:
			if serverName == "" {
				continue
			}
			plain.AddUint16(extensionServerName)
			plain.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8(0) // name_type = host_name
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(serverName))
					})
				})
			})
		case typ == extensionEncryptedClientHello:
			plain.AddUint16(extensionEncryptedClientHello)
			plain.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8(uint8(innerECHExt))
			})
		case typ == extensionSupportedVersions:
			var versions cryptobyte.String
			if !data.ReadUint8LengthPrefixed(&versions) || !data.Empty() {
				return nil, nil, errMalformed
			}
			plain.AddUint16(extensionSupportedVersions)
			plain.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					for !versions.Empty() {
						var v uint16
						if !versions.ReadUint16(&v) {
							b.SetError(errMalformed)
							return
						}
						// Every GREASE value is above TLS 1.3.
						if v >= VersionTLS13 {
							b.AddUint16(v)
						}
					}
				})
			})
		case echInnerCompressed[typ] || isGREASEUint16(typ):
			compressed.AddUint16(typ)
			compressed.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(data) })
			compressedTypes = append(compressedTypes, typ)
		default:
			plain.AddUint16(typ)
			plain.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(data) })
		}
	}
	plainExts, err := plain.Bytes()
	if err != nil {
		return nil, nil, err
	}
	compressedExts, err := compressed.Bytes()
	if err != nil {
		return nil, nil, err
	}
	var pskExt []byte
	if psk != nil {
		pskExt = make([]byte, psk.Len())
		if _, err := psk.Read(pskExt); err != nil && err != io.EOF {
			return nil, nil, err
		}
	}

	// hello writes the ClientHello body up to the extensions.
	hello := func(b *cryptobyte.Builder, sessionID []byte) {
		b.AddUint16(VersionTLS12)
		b.AddBytes(random)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sessionID) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, id := range innerSuites {
				b.AddUint16(id)
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(compressionNone) })
	}

	var ib cryptobyte.Builder
	ib.AddUint8(typeClientHello)
	ib.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		hello(b, sessionID)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(plainExts)
			b.AddBytes(compressedExts)
			b.AddBytes(pskExt)
		})
	})
	if inner, err = ib.Bytes(); err != nil {
		return nil, nil, err
	}
	if psk != nil {
		if err := psk.bindInner(inner); err != nil {
			return nil, nil, err
		}
		if _, err := psk.Read(pskExt); err != nil && err != io.EOF {
			return nil, nil, err
		}
		copy(inner[len(inner)-len(pskExt):], pskExt)
	}

	var eb cryptobyte.Builder
	hello(&eb, nil)
	eb.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(plainExts)
		if len(compressedTypes) > 0 {
			b.AddUint16(extensionECHOuterExtensions)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					for _, typ := range compressedTypes {
						b.AddUint16(typ)
					}
				})
			})
		}
		b.AddBytes(pskExt)
	})
	if encoded, err = eb.Bytes(); err != nil {
		return nil, nil, err
	}

	var paddingLen int
	if serverName != "" {
		paddingLen = max(0, maxNameLength-len(serverName))
	} else {
		paddingLen = maxNameLength + 9
	}
	paddingLen += 31 - ((len(encoded) + paddingLen - 1) % 32)
	return inner, append(encoded, make([]byte, paddingLen)...), nil
}

// bindInner sets the binder of e, the last extension of ClientHelloInner
// inner, as BoringSSL binds a PSK offered with ECH: over ClientHelloInner
// and, after a HelloRetryRequest, the inner transcript before it
// (ext_pre_shared_key_add_clienthello).
func (e *UtlsPreSharedKeyExtension) bindInner(inner []byte) error {
	bindersLen := 2
	for _, binder := range e.Binders {
		bindersLen += 1 + len(binder)
	}
	transcript := e.cipherSuite.hash.New()
	if len(e.prevClientHelloHash) > 0 {
		transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(e.prevClientHelloHash))})
		transcript.Write(e.prevClientHelloHash)
		if err := transcriptMsg(e.serverHello, transcript); err != nil {
			return err
		}
	}
	transcript.Write(inner[:len(inner)-bindersLen])
	e.Binders = [][]byte{e.cipherSuite.finishedHash(e.BinderKey, transcript)}
	return nil
}

// echPSK returns the PSK extension that carries the session to resume,
// which with ECH goes in ClientHelloInner only, or nil without a session.
// Only UtlsPreSharedKeyExtension can be bound to ClientHelloInner.
func (uconn *UConn) echPSK() (*UtlsPreSharedKeyExtension, error) {
	n := len(uconn.Extensions)
	if n == 0 {
		return nil, nil
	}
	ext, ok := uconn.Extensions[n-1].(PreSharedKeyExtension)
	if !ok || ext.Len() == 0 {
		return nil, nil
	}
	psk, ok := ext.(*UtlsPreSharedKeyExtension)
	if !ok {
		return nil, errors.New("tls: PSK resumption with a custom ECH ClientHello requires UtlsPreSharedKeyExtension")
	}
	return psk, nil
}

// marshalOuter marshals ClientHelloOuter, without the PSK extension, which
// BoringSSL never offers in ClientHelloOuter (should_offer_psk).
func (uconn *UConn) marshalOuter() error {
	exts := uconn.Extensions
	defer func() { uconn.Extensions = exts }()
	if n := len(exts); n > 0 {
		if _, ok := exts[n-1].(PreSharedKeyExtension); ok {
			uconn.Extensions = exts[:n-1]
		}
	}
	return uconn.MarshalClientHelloNoECH()
}
