package heysocks

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"
)

// Real account values from the Heysocks specification (section 6.4).
const (
	testSeed     = "61c814f99c622192323ac35362561bbf"
	testExtraHex = "31e43853c57d1f7a91910a887f858b97df4921ee047ff23f9f5fb87fb39fcf60013650b5021310adff2787da014e8dde0e25"
	testPassword = testSeed + ":" + testExtraHex
)

func TestKdfVector(t *testing.T) {
	key := Kdf(testSeed, 16)
	if hex.EncodeToString(key) != "73e12d799948a2bbc55efa3d9ef2d5bc" {
		t.Fatalf("key = %s, want 73e12d799948a2bbc55efa3d9ef2d5bc", hex.EncodeToString(key))
	}
	// The chain is concatenated, so a longer key extends the shorter one.
	longer := Kdf(testSeed, 32)
	if !bytes.Equal(longer[:16], key) {
		t.Fatal("Kdf is not a concatenated chain")
	}
	if len(Kdf(testSeed, 24)) != 24 {
		t.Fatal("Kdf ignored the requested size")
	}
}

func TestHeaderHMACVector(t *testing.T) {
	header := HeaderHMAC(testSeed)
	if hex.EncodeToString(header) != "32a2a4fc18ef03c26b4407a2c2e5e4d1" {
		t.Fatalf("H = %s, want 32a2a4fc18ef03c26b4407a2c2e5e4d1", hex.EncodeToString(header))
	}
	if len(header) != HeaderHMACSize {
		t.Fatalf("H length %d", len(header))
	}
	// The suffix is not the OneSocks one.
	oneSocks := md5.Sum([]byte(testSeed + "_onesocks"))
	if bytes.Equal(header, oneSocks[:]) {
		t.Fatal("header matches the OneSocks salt")
	}
}

func TestParsePasswordVector(t *testing.T) {
	seed, extra, key, err := ParsePassword("aes-128-ctr", testPassword)
	if err != nil {
		t.Fatalf("ParsePassword: %v", err)
	}
	if seed != testSeed {
		t.Fatalf("seed = %q", seed)
	}
	if hex.EncodeToString(key) != "73e12d799948a2bbc55efa3d9ef2d5bc" {
		t.Fatalf("key = %s", hex.EncodeToString(key))
	}
	if len(extra) != 50 {
		t.Fatalf("extra length = %d, want 50", len(extra))
	}
	if hex.EncodeToString(extra) != testExtraHex {
		t.Fatal("extra mismatch")
	}
	// Case insensitive, matching strings.ToUpper in the reference.
	if _, _, _, err = ParsePassword("AES-128-CTR", testPassword); err != nil {
		t.Fatalf("uppercase cipher rejected: %v", err)
	}
	// DUMMY disables encryption.
	_, _, dummyKey, err := ParsePassword("DUMMY", testPassword)
	if err != nil {
		t.Fatalf("dummy cipher rejected: %v", err)
	}
	if len(dummyKey) != 0 {
		t.Fatal("dummy cipher produced a key")
	}
	// No colon must fail loudly instead of panicking on an index.
	if _, _, _, err = ParsePassword("aes-128-ctr", "no-colon-here"); err == nil {
		t.Fatal("password without separator accepted")
	}
	if _, _, _, err = ParsePassword("aes-192-cfb", testPassword); err == nil {
		t.Fatal("unsupported cipher accepted")
	}
}

func TestPadding(t *testing.T) {
	minimum, maximum, err := PaddingRange("8-64")
	if err != nil {
		t.Fatalf("PaddingRange: %v", err)
	}
	if minimum != 8 || maximum != 64 {
		t.Fatalf("range = %d-%d", minimum, maximum)
	}
	seen := make(map[int]bool)
	for index := 0; index < 4096; index++ {
		value, err := RandomPadding(minimum, maximum)
		if err != nil {
			t.Fatalf("RandomPadding: %v", err)
		}
		if value < 8 || value > 63 {
			t.Fatalf("padding %d outside [8,63]: the upper bound must be exclusive", value)
		}
		seen[value] = true
	}
	if len(seen) < 40 {
		t.Fatalf("padding barely varies: %d distinct values", len(seen))
	}
	if value, _ := RandomPadding(0, 0); value != 0 {
		t.Fatalf("empty window produced %d", value)
	}
	if value, _ := RandomPadding(7, 8); value != 7 {
		t.Fatalf("\"7-8\" produced %d, want 7", value)
	}
	for _, invalid := range []string{"8", "a-b", "64-8", "0-256", "8-64-1"} {
		if _, _, err := PaddingRange(invalid); err == nil {
			t.Fatalf("padding_len %q accepted", invalid)
		}
	}
}

func TestHeaderBlockLayout(t *testing.T) {
	header := HeaderHMAC(testSeed)
	extra, err := hex.DecodeString(testExtraHex)
	if err != nil {
		t.Fatal(err)
	}
	iv := bytes.Repeat([]byte{0xAB}, IVSize)
	padding := bytes.Repeat([]byte{0x11}, 8)
	region := bytes.Repeat([]byte{0x22}, RandomRegionSize)

	block := HeaderBlockRandom(WireVariantDefault, header, padding, extra, iv, region)
	expected := make([]byte, 0, 2+len(padding)+len(extra)+len(header)+RandomRegionSize+1+IVSize)
	expected = append(expected, FrameMagic, byte(len(padding)))
	expected = append(expected, padding...)
	expected = append(expected, extra...)
	expected = append(expected, header...)
	expected = append(expected, region...)
	expected = append(expected, byte(IVSize))
	expected = append(expected, iv...)
	if !bytes.Equal(block, expected) {
		t.Fatalf("default layout mismatch:\n got %x\nwant %x", block, expected)
	}
	// The IV-size byte must land RandomRegionSize bytes after H, which is the
	// offset the reference clients hard code (0x90 = 16 + 128).
	offset := 2 + len(padding) + len(extra) + len(header) + RandomRegionSize
	if block[offset] != byte(IVSize) {
		t.Fatalf("IV size byte at %d = %#x, want %#x", offset, block[offset], IVSize)
	}
	if !bytes.Equal(block[offset+1:], iv) {
		t.Fatal("IV is not last")
	}
	// An empty padding argument still emits the length byte, so the peer can
	// always walk the block.
	short := HeaderBlockRandom(WireVariantDefault, header, nil, extra, iv, region)
	if short[0] != FrameMagic || short[1] != 0 {
		t.Fatalf("padding length byte = %#x/%d", short[0], short[1])
	}
}

func TestStreamRoundTrip(t *testing.T) {
	key := Kdf(testSeed, 16)
	iv, err := RandomIV()
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewStream(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewStream(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("the quick brown fox jumps over the lazy dog")
	encrypted := append([]byte(nil), payload...)
	writer.XORKeyStream(encrypted)
	if bytes.Equal(encrypted, payload) {
		t.Fatal("stream did not encrypt")
	}
	decrypted := append([]byte(nil), encrypted...)
	reader.XORKeyStream(decrypted)
	if !bytes.Equal(decrypted, payload) {
		t.Fatal("the peer stream did not recover the payload")
	}
	// The counter keeps running: decrypting the same bytes twice must not
	// return the plaintext again.
	replayed := append([]byte(nil), encrypted...)
	reader.XORKeyStream(replayed)
	if bytes.Equal(replayed, payload) {
		t.Fatal("CTR state reset between reads")
	}
	// Encrypting the same plaintext again must not repeat the ciphertext.
	again := append([]byte(nil), payload...)
	writer.XORKeyStream(again)
	if bytes.Equal(again, decryptOnly(reader, encrypted)) {
		t.Fatal("CTR state reset between writes")
	}
	// Two calls on one stream must equal one call on another stream at the same
	// key and IV: the counter is kept across calls.
	first := []byte("hello ")
	second := []byte("world")
	one := append(append([]byte(nil), first...), second...)
	single, _ := NewStream(key, iv)
	single.XORKeyStream(one)
	splitA, _ := NewStream(key, iv)
	separate := append([]byte(nil), first...)
	splitA.XORKeyStream(separate)
	rest := append([]byte(nil), second...)
	splitA.XORKeyStream(rest)
	if !bytes.Equal(one, append(separate, rest...)) {
		t.Fatal("per-call encryption differs from the continuous stream")
	}
	// A different IV must produce a different keystream.
	otherIV, _ := RandomIV()
	if bytes.Equal(iv, otherIV) {
		t.Fatal("RandomIV returned the same IV twice")
	}
	other, _ := NewStream(key, otherIV)
	otherPayload := append([]byte(nil), payload...)
	other.XORKeyStream(otherPayload)
	if bytes.Equal(otherPayload[len(otherPayload)-len(payload):], payload) {
		t.Fatal("independent IV produced the same keystream")
	}
	// The dummy cipher is a pass-through.
	dummy, err := NewStream(nil, iv)
	if err != nil {
		t.Fatal(err)
	}
	plain := append([]byte(nil), payload...)
	dummy.XORKeyStream(plain)
	if !bytes.Equal(plain, payload) {
		t.Fatal("dummy cipher modified the payload")
	}
	// IV length is enforced.
	if _, err = NewStream(key, []byte{1, 2, 3}); err == nil {
		t.Fatal("short IV accepted")
	}
}

func decryptOnly(stream *Stream, ciphertext []byte) []byte {
	buffer := append([]byte(nil), ciphertext...)
	stream.XORKeyStream(buffer)
	return buffer
}

func TestConnFraming(t *testing.T) {
	clientSide, peerSide := net.Pipe()
	defer clientSide.Close()
	defer peerSide.Close()
	key := Kdf(testSeed, 16)
	extra, _ := hex.DecodeString(testExtraHex)
	prefix := []byte("PREFIX-ADDR")
	conn := NewConn(clientSide, key, HeaderHMAC(testSeed), extra, prefix, 8, 64)

	payload := []byte("GET / HTTP/1.1\r\n\r\n")
	go func() {
		_, _ = conn.Write(payload)
	}()

	peer := make([]byte, 4096)
	_ = peerSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	// Header block (spec section 3.2):
	// 01 || P || padding[P] || extra || H[16] || random[128] || 0x10 || IV[16]
	blockPrefix := make([]byte, 2)
	if _, err := io.ReadFull(peerSide, blockPrefix); err != nil {
		t.Fatalf("read block prefix: %v", err)
	}
	if blockPrefix[0] != FrameMagic {
		t.Fatalf("frame magic = %#x", blockPrefix[0])
	}
	paddingLength := int(blockPrefix[1])
	if paddingLength < 8 || paddingLength > 63 {
		t.Fatalf("padding length %d outside [8,63]", paddingLength)
	}
	if _, err := io.ReadFull(peerSide, make([]byte, paddingLength)); err != nil {
		t.Fatalf("read padding: %v", err)
	}
	extraBytes := make([]byte, len(extra))
	if _, err := io.ReadFull(peerSide, extraBytes); err != nil {
		t.Fatalf("read extra: %v", err)
	}
	if !bytes.Equal(extraBytes, extra) {
		t.Fatal("extra mismatch on the wire")
	}
	head := make([]byte, 16)
	if _, err := io.ReadFull(peerSide, head); err != nil {
		t.Fatalf("read H: %v", err)
	}
	if !bytes.Equal(head, HeaderHMAC(testSeed)) {
		t.Fatal("H mismatch on the wire")
	}
	if _, err := io.ReadFull(peerSide, make([]byte, RandomRegionSize)); err != nil {
		t.Fatalf("read random region: %v", err)
	}
	sizeByte := make([]byte, 1)
	if _, err := io.ReadFull(peerSide, sizeByte); err != nil {
		t.Fatalf("read IV size: %v", err)
	}
	if sizeByte[0] != byte(IVSize) {
		t.Fatalf("IV size byte = %d, want %d", sizeByte[0], IVSize)
	}
	iv := make([]byte, IVSize)
	if _, err := io.ReadFull(peerSide, iv); err != nil {
		t.Fatalf("read IV: %v", err)
	}
	ciphertext := make([]byte, len(prefix)+len(payload))
	if _, err := io.ReadFull(peerSide, ciphertext); err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	reader, err := NewStream(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	plain := append([]byte(nil), ciphertext...)
	reader.XORKeyStream(plain)
	if !bytes.Equal(plain[:len(prefix)+len(payload)], append(append([]byte(nil), prefix...), payload...)) {
		t.Fatalf("plaintext = %q", plain[:len(prefix)+len(payload)])
	}
	_ = peer
	deadline := time.Now().Add(2 * time.Second)
	for !conn.WriterReplaceable() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !conn.WriterReplaceable() {
		t.Fatal("writer not marked replaceable after the first write")
	}
}

func TestConnReadSideIV(t *testing.T) {
	clientSide, peerSide := net.Pipe()
	defer clientSide.Close()
	defer peerSide.Close()
	key := Kdf(testSeed, 16)
	conn := NewConn(clientSide, key, HeaderHMAC(testSeed), nil, nil, 0, 0)

	iv := make([]byte, IVSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	message := []byte("downstream payload")
	writer, _ := NewStream(key, iv)
	ciphertext := append([]byte(nil), message...)
	writer.XORKeyStream(ciphertext)
	go func() {
		// Peer block, homogeneous with ours (spec section 3.4). This conn was
		// built without extra, so only the prefix, H, the random region, the
		// size byte and the IV are on the wire.
		block := []byte{FrameMagic, 0}
		block = append(block, HeaderHMAC(testSeed)...)
		block = append(block, make([]byte, RandomRegionSize)...)
		block = append(block, byte(IVSize))
		block = append(block, iv...)
		_, _ = peerSide.Write(append(block, ciphertext...))
	}()
	buffer := make([]byte, len(message))
	if _, err := io.ReadFull(conn, buffer); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buffer, message) {
		t.Fatalf("plaintext = %q", buffer)
	}
	if !conn.ReaderReplaceable() {
		t.Fatal("reader not marked replaceable after the IV")
	}
}

func TestHeaderBlockVariants(t *testing.T) {
	header := HeaderHMAC(testSeed)
	extra := []byte("EXTRA")
	padding := []byte("PAD")
	iv := []byte("0123456789abcdef")
	region := bytes.Repeat([]byte{0x33}, RandomRegionSize)
	prefix := append([]byte{FrameMagic, byte(len(padding))}, padding...)

	base := HeaderBlockRandom(WireVariantDefault, header, padding, extra, iv, region)
	expectedBase := append(append(append(append(append(append([]byte{}, prefix...), extra...), header...), region...), byte(IVSize)), iv...)
	if !bytes.Equal(base, expectedBase) {
		t.Fatalf("default variant mismatch:\n got %x\nwant %x", base, expectedBase)
	}

	separated := HeaderBlockRandom(WireVariantRandSeparated, header, padding, extra, iv, region)
	expectedSeparated := append(append(append(append(append(append([]byte{}, prefix...), header...), region...), extra...), byte(IVSize)), iv...)
	if !bytes.Equal(separated, expectedSeparated) {
		t.Fatal("rand-separated variant mismatch")
	}

	noExtra := HeaderBlockRandom(WireVariantNoExtra, header, padding, extra, iv, region)
	expectedNoExtra := append(append(append(append(append([]byte{}, prefix...), header...), region...), byte(IVSize)), iv...)
	if !bytes.Equal(noExtra, expectedNoExtra) {
		t.Fatal("no-extra variant mismatch")
	}

	legacy := HeaderBlockRandom(WireVariantLegacy, header, padding, extra, iv, region)
	expectedLegacy := append(append(append(append(append([]byte{}, header...), padding...), extra...), byte(IVSize)), iv...)
	if !bytes.Equal(legacy, expectedLegacy) {
		t.Fatal("legacy variant mismatch")
	}

	for _, invalid := range []string{"nope", "Default", "extra-first", "version-prefix", "no-size-byte"} {
		if _, err := NormalizeWireVariant(invalid); err == nil {
			t.Fatalf("wire_variant %q accepted", invalid)
		}
	}
	for _, valid := range []string{"", "default", "rand-separated", "no-extra", "legacy"} {
		if _, err := NormalizeWireVariant(valid); err != nil {
			t.Fatalf("wire_variant %q rejected: %v", valid, err)
		}
	}
	for _, valid := range []string{"", "iv", "hmac-iv"} {
		if _, err := NormalizeReadVariant(valid); err != nil {
			t.Fatalf("read_variant %q rejected: %v", valid, err)
		}
	}
	if _, err := NormalizeReadVariant("weird"); err == nil {
		t.Fatal("read_variant weird accepted")
	}
}
