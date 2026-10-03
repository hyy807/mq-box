//go:build with_utls

package tls

import (
	"testing"

	utls "github.com/metacubex/utls"
)

// The reference Heysocks kernel links sagernet/utls
// v0.0.0-20230309024959-6732c2ab36f2, where HelloChrome_Auto resolves to
// HelloChrome_106_Shuffle. The bundled fork's HelloChrome_Auto is Chrome 133,
// so the fingerprint has to be selected by an explicit name.
func TestChrome106FingerprintName(t *testing.T) {
	id, err := uTLSClientHelloID("chrome_106")
	if err != nil {
		t.Fatal(err)
	}
	if id != utls.HelloChrome_106_Shuffle {
		t.Fatalf("chrome_106 resolved to %v", id)
	}
	for _, alias := range []string{"chrome106", "chrome_106_shuffle"} {
		other, err := uTLSClientHelloID(alias)
		if err != nil || other != utls.HelloChrome_106_Shuffle {
			t.Fatalf("alias %q did not resolve to Chrome 106: %v %v", alias, other, err)
		}
	}
	// The plain name stays at the fork's default (Chrome 133): sharing a name
	// with a different profile is exactly the trap this test guards.
	auto, err := uTLSClientHelloID("chrome")
	if err != nil {
		t.Fatal(err)
	}
	if auto == utls.HelloChrome_106_Shuffle {
		t.Fatal("chrome must stay distinct from chrome_106")
	}
}

// Pins the wire shape the specification extracted from the official kernel:
// GREASE, ALPS, brotli-only compress_certificate, no post-quantum key share.
func TestChrome106SpecMatchesReferenceKernel(t *testing.T) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_106_Shuffle)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.CipherSuites) == 0 || spec.CipherSuites[0] != utls.GREASE_PLACEHOLDER {
		t.Fatalf("first cipher suite must be GREASE: %x", spec.CipherSuites)
	}
	var hasSha256Cbc, hasRsaKex bool
	for _, suite := range spec.CipherSuites {
		switch suite {
		case utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
			hasSha256Cbc = true
		case utls.TLS_RSA_WITH_AES_256_CBC_SHA:
			hasRsaKex = true
		}
	}
	if !hasSha256Cbc || !hasRsaKex {
		t.Fatalf("cipher suite set is not the Chrome 106 baseline: %x", spec.CipherSuites)
	}
	if len(spec.CompressionMethods) != 1 || spec.CompressionMethods[0] != 0 {
		t.Fatalf("compression methods: %x", spec.CompressionMethods)
	}
	var (
		hasAlps, hasBrotliOnly, hasGreaseExtension, hasPadding, hasSni bool
		hasPqKeyShare, hasEch                                          bool
	)
	for _, extension := range spec.Extensions {
		switch typed := extension.(type) {
		case *utls.ApplicationSettingsExtension:
			hasAlps = len(typed.SupportedProtocols) == 1 && typed.SupportedProtocols[0] == "h2"
		case *utls.UtlsCompressCertExtension:
			hasBrotliOnly = len(typed.Algorithms) == 1 && typed.Algorithms[0] == utls.CertCompressionBrotli
		case *utls.UtlsGREASEExtension:
			hasGreaseExtension = true
		case *utls.UtlsPaddingExtension:
			hasPadding = typed.GetPaddingLen != nil
		case *utls.SNIExtension:
			hasSni = true
		case *utls.KeyShareExtension:
			for _, share := range typed.KeyShares {
				switch share.Group {
				case utls.X25519, utls.CurveP256, utls.CurveP384, utls.GREASE_PLACEHOLDER:
				default:
					hasPqKeyShare = true
				}
			}
		}
		if generic, isGeneric := extension.(*utls.GenericExtension); isGeneric && generic.Id == 0xfe0d {
			hasEch = true
		}
	}
	if !hasSni || !hasAlps || !hasBrotliOnly || !hasGreaseExtension || !hasPadding {
		t.Fatalf("missing required extension: sni=%v alps=%v brotli_only=%v grease=%v padding=%v",
			hasSni, hasAlps, hasBrotliOnly, hasGreaseExtension, hasPadding)
	}
	if hasPqKeyShare {
		t.Fatal("Chrome 106 must not offer a post-quantum key share")
	}
	if hasEch {
		t.Fatal("Chrome 106 must not offer encrypted client hello")
	}
}

// The padding rule the specification quoted: pad only when the ClientHello
// lands between 256 and 511 bytes, and never below five bytes of padding.
func TestChrome106BoringPaddingRule(t *testing.T) {
	for _, testCase := range []struct {
		length     int
		wantPad    bool
		wantLength int
	}{
		{200, false, 0},
		{256, true, 0x200 - 256 - 4},
		{400, true, 0x200 - 400 - 4},
		{511, true, 1},
		{512, false, 0},
		{600, false, 0},
	} {
		length, willPad := utls.BoringPaddingStyle(testCase.length)
		if willPad != testCase.wantPad {
			t.Fatalf("BoringPaddingStyle(%d): willPad=%v", testCase.length, willPad)
		}
		if willPad && length != testCase.wantLength {
			t.Fatalf("BoringPaddingStyle(%d) = %d, want %d", testCase.length, length, testCase.wantLength)
		}
	}
}
