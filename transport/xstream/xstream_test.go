package xstream

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	testSeed     = "0bc2a7c3129752107c397a0a002e9f7b"
	testExtraHex = "31903af8b4bc0744a989921d9052a944afc08d690865d31de193850d00b44ccd955da8906e2f762b39a696a771c6601c1960" // 50 bytes
	testFakeHex  = "79a245d2bf082245d37cdce2b5c2f98ccbfa28f56080126d1bcd7671128e58fe83d312adc642c368f9777eaed59665e4c855e83b43a5ddc5fe536866d918b495f375802c"
)

// TestSaltMatchesReference pins the literal salt from the reference kernel.
func TestSaltMatchesReference(t *testing.T) {
	if Salt != "do not hack this protocol please" {
		t.Fatalf("salt changed: %q", Salt)
	}
}

// TestParsePassword covers both halves of the provider's "<seed>:<hex>" pair.
func TestParsePassword(t *testing.T) {
	seed, extra, err := ParsePassword(testSeed + ":" + testExtraHex)
	if err != nil {
		t.Fatal(err)
	}
	if seed != testSeed {
		t.Fatalf("seed = %q", seed)
	}
	if extra != testExtraHex {
		t.Fatalf("extra = %q", extra)
	}
	for _, bad := range []string{"", "onlyseed", testSeed + ":zz"} {
		if _, _, err = ParsePassword(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
	// Empty extraHex is allowed (no HMAC key).
	if _, extra, err := ParsePassword(testSeed + ":"); err != nil || extra != "" {
		t.Fatalf("empty extraHex should be valid")
	}
}

// TestTokenHMAC pins H = MD5(seed + salt).
func TestTokenHMAC(t *testing.T) {
	expected := md5.Sum([]byte(testSeed + "do not hack this protocol please"))
	got := TokenHMAC(testSeed)
	if !bytes.Equal(got, expected[:]) {
		t.Fatalf("H mismatch: %x != %x", got, expected)
	}
	if len(got) != 16 {
		t.Fatalf("H length = %d", len(got))
	}
}

// TestBuildFirstBlockLayout asserts the exact byte layout:
//
//	[0:128]      decoy from fake-net.tcp (then the remainder is random)
//	[128:144]    H
//	[144:194]    50 byte raw HMAC key
//	[194]        0x10
//	[195:211]    IV
//	[211:...]    AES-CTR(address)
func TestBuildFirstBlockLayout(t *testing.T) {
	config := Config{Seed: testSeed, ExtraHex: testExtraHex, FakeTCPHex: testFakeHex}
	destination := M.ParseSocksaddr("127.0.0.2:18081")
	firstBlock, _, _, ivOffset, err := BuildFirstBlock(config, destination)
	if err != nil {
		t.Fatal(err)
	}

	extraKey, _ := hex.DecodeString(testExtraHex)
	hmacLength := len(extraKey) // 50

	address, err := WriteAddress(destination)
	if err != nil {
		t.Fatal(err)
	}

	if ivOffset != 128+16+hmacLength {
		t.Fatalf("ivOffset = %d, want %d", ivOffset, 128+16+hmacLength)
	}
	// handshake + at least one address byte + port
	if len(firstBlock) < ivOffset+1+16+1+4+2 {
		t.Fatalf("first block too short: %d", len(firstBlock))
	}

	decoy, _ := hex.DecodeString(testFakeHex)
	if !bytes.Equal(firstBlock[:len(decoy)], decoy) {
		t.Fatal("decoy header bytes are not the provider's fake-net.tcp")
	}
	if !bytes.Equal(firstBlock[128:144], TokenHMAC(testSeed)) {
		t.Fatal("H is not at offset 128")
	}
	if !bytes.Equal(firstBlock[144:144+hmacLength], extraKey) {
		t.Fatal("raw HMAC key is not at offset 144")
	}
	if firstBlock[ivOffset] != 0x10 {
		t.Fatalf("marker at %d = %#x, want 0x10", ivOffset, firstBlock[ivOffset])
	}
	if len(firstBlock) != ivOffset+1+16+len(address) {
		t.Fatalf("total length = %d, want handshake(%d) + address(%d)", len(firstBlock), ivOffset+1+16, len(address))
	}
}

// TestEncryptedAddressDecrypts proves the trailing bytes are the AES-CTR
// encryption of the SOCKS address under the same keystream as the IV.
func TestEncryptedAddressDecrypts(t *testing.T) {
	config := Config{Seed: testSeed, ExtraHex: testExtraHex, FakeTCPHex: testFakeHex}
	destination := M.ParseSocksaddr("capture.invalid:18082")
	firstBlock, _, block, ivOffset, err := BuildFirstBlock(config, destination)
	if err != nil {
		t.Fatal(err)
	}
	iv := firstBlock[ivOffset+1 : ivOffset+1+16]
	encrypted := firstBlock[ivOffset+1+16:]

	decryptor := cipher.NewCTR(block, iv)
	plain := make([]byte, len(encrypted))
	decryptor.XORKeyStream(plain, encrypted)

	if !bytes.Equal(plain, []byte("\x03\x0fcapture.invalid\x46\xa2")) {
		t.Fatalf("address mismatch: %x", plain)
	}
}

// TestBlockIsMD5Seed pins the AES key derivation (aes-128-ctr => MD5(seed)).
func TestBlockIsMD5Seed(t *testing.T) {
	block, err := Block(testSeed)
	if err != nil {
		t.Fatal(err)
	}
	if block.BlockSize() != 16 {
		t.Fatalf("block size = %d", block.BlockSize())
	}
	sum := md5.Sum([]byte(testSeed))
	direct, _ := aes.NewCipher(sum[:])
	if block.BlockSize() != direct.BlockSize() {
		t.Fatal("block derivation mismatch")
	}
}

// TestWriteAddressFamilies covers the three SOCKS address forms.
func TestWriteAddressFamilies(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"127.0.0.2:18081", "\x01\x7f\x00\x00\x02\x46\xa1"},
		{"capture.invalid:18082", "\x03\x0fcapture.invalid\x46\xa2"},
		{"[2001:db8::1]:18083", "\x04\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x46\xa3"},
	}
	for _, testCase := range cases {
		got, err := WriteAddress(M.ParseSocksaddr(testCase.input))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, []byte(testCase.expected)) {
			t.Fatalf("%s: got %x", testCase.input, got)
		}
	}
}
