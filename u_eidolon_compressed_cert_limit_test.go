package tls

import (
	"bytes"
	"testing"
)

// [eidolon] A compressed Certificate may not decompress to more than an
// uncompressed Certificate may carry (RFC 8879, Section 5). The advertised
// length is checked before allocating, and the client sends illegal_parameter
// as BoringSSL does. Before the fix, up to 16 MiB were allocated and a
// message over maxHandshakeCertificateMsg was accepted.
func TestEidolonCompressedCertificateSizeLimit(t *testing.T) {
	// The certificate_list framing of one entry adds 1+3+3+2 bytes.
	const framing = 9
	codecs := append(certificateTestCodecs[:len(certificateTestCodecs):len(certificateTestCodecs)], struct {
		name      string
		algorithm CertCompressionAlgo
		compress  func(*testing.T, []byte) []byte
	}{"brotli", CertCompressionBrotli, func(t *testing.T, body []byte) []byte {
		return compressBrotliTestCertificate(t, body, 22)
	}})
	for _, codec := range codecs {
		t.Run(codec.name, func(t *testing.T) {
			for _, test := range []struct {
				name   string
				size   int // decompressed message size
				length uint32
				ok     bool
			}{
				{"at_limit", maxHandshakeCertificateMsg, maxHandshakeCertificateMsg, true},
				{"over_limit", maxHandshakeCertificateMsg + 1, maxHandshakeCertificateMsg + 1, false},
				{"advertised_max_uint24", 64, 1<<24 - 1, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					body := marshalCompressionTestCertificate(t, bytes.Repeat([]byte{'c'}, test.size-framing))
					if len(body) != test.size {
						t.Fatalf("test body is %d bytes, want %d", len(body), test.size)
					}
					hs := compressionTestHandshake(codec.algorithm)
					got, err := hs.decompressCert(utlsCompressedCertificateMsg{
						algorithm:                    uint16(codec.algorithm),
						uncompressedLength:           test.length,
						compressedCertificateMessage: codec.compress(t, body),
					})
					if test.ok {
						if err != nil || got == nil {
							t.Fatalf("rejected a certificate message at the limit: %v", err)
						}
						return
					}
					if err == nil || got != nil {
						t.Fatal("accepted a compressed certificate message over the size limit")
					}
					alertRecord := hs.c.sendBuf
					if len(alertRecord) != recordHeaderLen+2 || alertRecord[0] != byte(recordTypeAlert) ||
						alertRecord[recordHeaderLen] != alertLevelError || alertRecord[recordHeaderLen+1] != byte(alertIllegalParameter) {
						t.Fatalf("sent alert %x, want illegal_parameter", alertRecord)
					}
				})
			}
		})
	}
}
