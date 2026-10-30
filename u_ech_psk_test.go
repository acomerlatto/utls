// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"
)

const utlsTestECHConfigsHex = "0045fe0d0041590020002092a01233db2218518ccbbbbc24df20686af417b37388de6460e94011974777090004000100010012636c6f7564666c6172652d6563682e636f6d0000"

func TestUTLSECHPreSharedKeyPrivacy(t *testing.T) {
	// This is the supported X25519 ECHConfigList used in ech_test.go. A
	// server private key is unnecessary when inspecting ClientHelloOuter.
	echConfigs, err := hex.DecodeString(utlsTestECHConfigsHex)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		realECH   bool
		populated bool
	}{
		{name: "RealECHWithPSK", realECH: true, populated: true},
		{name: "RealECHWithEmptyPSK", realECH: true},
		{name: "GREASEECHWithPSK", populated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{ServerName: "private.example", InsecureSkipVerify: true, OmitEmptyPsk: true}
			if tc.realECH {
				config.EncryptedClientHelloConfigList = echConfigs
			}
			client := UClient(nil, config, HelloChrome_120)
			if err := client.BuildHandshakeStateWithoutSession(); err != nil {
				t.Fatal(err)
			}

			label := []byte("private-session-ticket-visible-in-ech-outer")
			psk := &UtlsPreSharedKeyExtension{OmitEmptyPsk: true}
			if tc.populated {
				// Model an initialized extension after the session controller has
				// loaded a ticket, immediately before ClientHello serialization.
				psk.InitializeByUtls(&SessionState{version: VersionTLS13, cipherSuite: TLS_AES_128_GCM_SHA256},
					make([]byte, 32), make([]byte, 32), []PskIdentity{{Label: label}})
			}
			client.Extensions = append(client.Extensions, psk)

			if err := client.MarshalClientHello(); err != nil {
				t.Fatal(err)
			}
			outer := new(clientHelloMsg)
			if !outer.unmarshal(client.HandshakeState.Hello.Raw) {
				t.Fatal("invalid marshaled ClientHello")
			}
			if len(outer.encryptedClientHello) == 0 {
				t.Fatal("missing ECH extension")
			}
			// [eidolon] With real ECH, the PSK is in ClientHelloInner only.
			if tc.realECH && tc.populated {
				if bytes.Contains(client.HandshakeState.Hello.Raw, label) || len(outer.pskIdentities) != 0 {
					t.Fatal("real ECH exposed the PSK in ClientHelloOuter")
				}
				if inner := client.echCtx.innerHello; len(inner.pskIdentities) != 1 || !bytes.Equal(inner.pskIdentities[0].label, label) {
					t.Fatal("real ECH left the PSK out of ClientHelloInner")
				}
			} else if tc.populated {
				if len(outer.pskIdentities) != 1 || !bytes.Equal(outer.pskIdentities[0].label, label) {
					t.Fatal("GREASE ECH removed the ordinary PSK identity")
				}
			} else if len(outer.pskIdentities) != 0 {
				t.Fatal("empty PSK extension was not omitted")
			}
		})
	}
}

func TestUTLSECHCachedSessionPrivacy(t *testing.T) {
	echConfigs, err := hex.DecodeString(utlsTestECHConfigsHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, realECH := range []bool{false, true} {
		name := "GREASEECH"
		if realECH {
			name = "RealECH"
		}
		t.Run(name, func(t *testing.T) {
			config := testConfigClient.Clone()
			config.ServerName = "private.example"
			config.InsecureSkipVerify = true
			config.ClientSessionCache = NewLRUClientSessionCache(1)
			config.OmitEmptyPsk = true
			if realECH {
				config.EncryptedClientHelloConfigList = echConfigs
			}
			label := []byte("cached-private-session-ticket")
			config.ClientSessionCache.Put(config.ServerName, &ClientSessionState{session: &SessionState{
				version:          VersionTLS13,
				cipherSuite:      TLS_AES_128_GCM_SHA256,
				createdAt:        uint64(config.time().Unix()),
				useBy:            uint64(config.time().Add(time.Hour).Unix()),
				secret:           bytes.Repeat([]byte{1}, 32),
				peerCertificates: []*x509.Certificate{testECDSAP256Cert.Leaf},
				ticket:           label,
			}})
			preset, err := UTLSIdToSpec(HelloChrome_120)
			if err != nil {
				t.Fatal(err)
			}
			preset.Extensions = append(preset.Extensions, &UtlsPreSharedKeyExtension{})
			client := UClient(nil, config, HelloCustom)
			if err := client.ApplyPreset(&preset); err != nil {
				t.Fatal(err)
			}
			if err := client.BuildHandshakeState(); err != nil {
				t.Fatal(err)
			}
			outer := new(clientHelloMsg)
			if !outer.unmarshal(client.HandshakeState.Hello.Raw) {
				t.Fatal("invalid ClientHello")
			}
			// [eidolon] With real ECH, the session is in ClientHelloInner
			// only, with its binder.
			hello := outer
			if realECH {
				if bytes.Contains(client.HandshakeState.Hello.Raw, label) || len(outer.pskIdentities) != 0 {
					t.Fatal("real ECH exposed the cached session in ClientHelloOuter")
				}
				hello = client.echCtx.innerHello
			}
			if len(hello.pskIdentities) != 1 || !bytes.Equal(hello.pskIdentities[0].label, label) {
				t.Fatal("the cached session was not loaded")
			}
			if len(hello.pskBinders) != 1 || len(hello.pskBinders[0]) != 32 || bytes.Equal(hello.pskBinders[0], make([]byte, 32)) {
				t.Fatal("the cached session's binder was not computed")
			}
		})
	}
}
