package onesocks

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// testPassword is the ASCII password used by the reference documents, so the
// vectors below can be recomputed independently (python hashlib md5 chain).
const testPassword = "0123456789abcdef0123456789abcdef"

func TestDeriveVectors(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		actual []byte
		want   string
	}{
		{"h", PasswordHMAC(testPassword), "cf5cd746cc7e1d2c0a7d6309ce2b8203"},
		{"key16", PasswordKey(testPassword, 16), "8516ac99dc60603295de7bdb6a153530"},
		{"key32", PasswordKey(testPassword, 32), "8516ac99dc60603295de7bdb6a153530ddc2ba774e90ccb5a0d03f7138f0c41d"},
	} {
		if got := hex.EncodeToString(testCase.actual); got != testCase.want {
			t.Fatalf("%s = %s, want %s", testCase.name, got, testCase.want)
		}
	}
	// The salt must not be the xstream one; the two constants are not
	// interchangeable.
	if ProtocolSalt != "_onesocks" {
		t.Fatalf("salt = %q", ProtocolSalt)
	}
	if bytes.Contains([]byte(ProtocolSalt), []byte("do not hack")) {
		t.Fatal("the xstream salt must not be reused")
	}
}

func TestCipherKeySize(t *testing.T) {
	for name, want := range map[string]int{"": 16, "aes-128-ctr": 16, "AES-256-CTR": 32, "aes-192-ctr": 24} {
		size, err := CipherKeySize(name)
		if err != nil {
			t.Fatalf("CipherKeySize(%q): %v", name, err)
		}
		if size != want {
			t.Fatalf("CipherKeySize(%q) = %d, want %d", name, size, want)
		}
	}
	if _, err := CipherKeySize("chacha20"); err == nil {
		t.Fatal("unsupported cipher must fail")
	}
}

func TestAddressEncoding(t *testing.T) {
	for _, testCase := range []struct {
		destination M.Socksaddr
		want        string
	}{
		{M.Socksaddr{Addr: netip.MustParseAddr("127.0.0.2"), Port: 18081}, "017f00000246a1"},
		{M.Socksaddr{Fqdn: "capture.invalid", Port: 18082}, "030f636170747572652e696e76616c696446a2"},
		{M.Socksaddr{Addr: netip.MustParseAddr("2001:db8::1"), Port: 18083}, "0420010db800000000000000000000000146a3"},
	} {
		encoded, err := WriteAddress(nil, testCase.destination)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(encoded); got != testCase.want {
			t.Fatalf("%s = %s, want %s", testCase.destination, got, testCase.want)
		}
		length, err := AddressLength(testCase.destination)
		if err != nil {
			t.Fatal(err)
		}
		if length != len(encoded) {
			t.Fatalf("AddressLength(%s) = %d, encoded %d", testCase.destination, length, len(encoded))
		}
		decoded, err := ReadAddress(bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		if decoded.String() != testCase.destination.String() {
			t.Fatalf("round trip %s -> %s", testCase.destination, decoded)
		}
	}
}

func TestPaddingWindow(t *testing.T) {
	paddingRange, err := ParsePadding("8-64")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[int]bool)
	for index := 0; index < 4000; index++ {
		length := paddingRange.Pick()
		if length < 8 || length > 63 {
			t.Fatalf("padding %d outside 8..63", length)
		}
		seen[length] = true
	}
	if len(seen) < 40 {
		t.Fatalf("padding window is not random enough: %d distinct values", len(seen))
	}
	for spec, want := range map[string]int{"": 0, "0-0": 0, "7-8": 7, "12-12": 0} {
		parsed, err := ParsePadding(spec)
		if err != nil {
			t.Fatalf("ParsePadding(%q): %v", spec, err)
		}
		if got := parsed.Pick(); got != want {
			t.Fatalf("ParsePadding(%q).Pick() = %d, want %d", spec, got, want)
		}
	}
	if _, err := ParsePadding("8"); err == nil {
		t.Fatal("malformed padding must fail")
	}
	if _, err := ParsePadding("300-400"); err == nil {
		t.Fatal("padding above 255 must fail")
	}
}

func TestBuildHeaderLayout(t *testing.T) {
	hmac := PasswordHMAC(testPassword)
	iv, err := RandomIV()
	if err != nil {
		t.Fatal(err)
	}
	header, err := BuildHeader(hmac, 9, iv)
	if err != nil {
		t.Fatal(err)
	}
	if header[0] != FrameMagic || header[1] != 9 {
		t.Fatalf("magic/padding = %#x/%d", header[0], header[1])
	}
	if !bytes.Equal(header[2+9:2+9+16], hmac) {
		t.Fatal("hmac is not at 2+padding")
	}
	if header[2+9+16] != 0x10 {
		t.Fatalf("iv length byte = %#x", header[2+9+16])
	}
	if !bytes.Equal(header[2+9+17:], iv) {
		t.Fatal("iv is not the last field")
	}
	if len(header) != 2+9+16+1+16 {
		t.Fatalf("header length = %d", len(header))
	}
}

// TestDialAgainstFakeServer drives the whole framing against a reference server
// that follows the published layout.
func TestDialAgainstFakeServer(t *testing.T) {
	key := PasswordKey(testPassword, 16)
	hmac := PasswordHMAC(testPassword)
	paddingRange, err := ParsePadding("8-64")
	if err != nil {
		t.Fatal(err)
	}
	destination := M.Socksaddr{Addr: netip.MustParseAddr("127.0.0.2"), Port: 18081}

	clientSide, serverSide := net.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serveReference(serverSide, key, hmac, destination, hmac, []byte("pong-from-server"))
	}()

	conn, err := Dial(clientSide, key, hmac, paddingRange, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	request := []byte("ping-from-client")
	if _, err = conn.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("pong-from-server"))
	if _, err = io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(reply) != "pong-from-server" {
		t.Fatalf("reply = %q", reply)
	}
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialRejectsBadServerHMAC(t *testing.T) {
	key := PasswordKey(testPassword, 16)
	hmac := PasswordHMAC(testPassword)
	destination := M.Socksaddr{Addr: netip.MustParseAddr("127.0.0.2"), Port: 18081}

	clientSide, serverSide := net.Pipe()
	go func() {
		// The server answers with a valid block but a foreign H, and no payload,
		// so the client must reject it instead of blocking on the pipe.
		_ = serveReference(serverSide, key, hmac, destination, []byte("0123456789abcdef"), nil)
	}()

	conn, err := Dial(clientSide, key, hmac, PaddingRange{}, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("ping-from-client")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	if _, err = conn.Read(buffer); err == nil {
		t.Fatal("a server hmac mismatch must fail the read")
	}
}

// serveReference implements the server half of the published framing: it
// validates the client block, decodes the destination address, verifies the
// payload and answers with its own block plus an encrypted reply.
func serveReference(conn net.Conn, key []byte, hmac []byte, expectedDestination M.Socksaddr, responseHMAC []byte, replyPayload []byte) error {
	defer conn.Close()

	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return E.Cause(err, "server: read magic")
	}
	if head[0] != FrameMagic {
		return fmt.Errorf("server: magic = %#x", head[0])
	}
	padding := int(head[1])
	if padding < 0 || padding > 255 {
		return fmt.Errorf("server: padding = %d", padding)
	}
	rest := make([]byte, padding+HeaderHMACSize+1+IVSize)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return E.Cause(err, "server: read block")
	}
	if !bytes.Equal(rest[padding:padding+HeaderHMACSize], hmac) {
		return errors.New("server: client hmac mismatch")
	}
	if rest[padding+HeaderHMACSize] != 0x10 {
		return fmt.Errorf("server: iv length = %#x", rest[padding+HeaderHMACSize])
	}
	iv := rest[padding+HeaderHMACSize+1 : padding+HeaderHMACSize+1+IVSize]
	readStream, err := NewCTR(key, iv)
	if err != nil {
		return err
	}

	addressLength, err := AddressLength(expectedDestination)
	if err != nil {
		return err
	}
	encryptedAddress := make([]byte, addressLength)
	if _, err = io.ReadFull(conn, encryptedAddress); err != nil {
		return E.Cause(err, "server: read address")
	}
	addressBytes := make([]byte, addressLength)
	readStream.XORKeyStream(addressBytes, encryptedAddress)
	decoded, err := ReadAddress(bytes.NewReader(addressBytes))
	if err != nil {
		return err
	}
	if decoded.String() != expectedDestination.String() {
		return fmt.Errorf("server: destination = %s, want %s", decoded, expectedDestination)
	}

	payload := make([]byte, len("ping-from-client"))
	if _, err = io.ReadFull(conn, payload); err != nil {
		return E.Cause(err, "server: read payload")
	}
	plain := make([]byte, len(payload))
	readStream.XORKeyStream(plain, payload)
	if string(plain) != "ping-from-client" {
		return fmt.Errorf("server: payload = %q", plain)
	}

	responseIV, err := RandomIV()
	if err != nil {
		return err
	}
	writeStream, err := NewCTR(key, responseIV)
	if err != nil {
		return err
	}
	header, err := BuildHeader(responseHMAC, 8, responseIV)
	if err != nil {
		return err
	}
	response := make([]byte, 0, len(header)+len(replyPayload))
	response = append(response, header...)
	if len(replyPayload) > 0 {
		encryptedReply := make([]byte, len(replyPayload))
		writeStream.XORKeyStream(encryptedReply, replyPayload)
		response = append(response, encryptedReply...)
	}
	_, err = conn.Write(response)
	return err
}
