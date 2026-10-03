package xhttp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/xstream"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	testSeed     = "0bc2a7c3129752107c397a0a002e9f7b"
	testExtraHex = "31903af8b4bc0744a989921d9052a944afc08d690865d31de193850d00b44ccd955da8906e2f762b39a696a771c6601c1960"
	testFakeHex  = "79a245d2bf082245d37cdce2b5c2f98ccbfa28f56080126d1bcd7671128e58fe83d312adc642c368f9777eaed59665e4c855e83b43a5ddc5fe536866d918b495f375802c"
)

// fakeServer implements the server half of the reference wire format:
// read 128+16+key bytes, the 0x10 marker, then a 16 byte IV, then AES-CTR data.
type fakeServer struct {
	listener   net.Listener
	done       chan struct{}
	sawAddress string
}

func startFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &fakeServer{listener: listener, done: make(chan struct{})}
	go server.serve()
	return server
}

func (s *fakeServer) serve() {
	defer close(s.done)
	conn, err := s.listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	extraKey, _ := hex.DecodeString(testExtraHex)
	baseLength := 128 + 16 + len(extraKey)

	base := make([]byte, baseLength)
	if _, err = io.ReadFull(conn, base); err != nil {
		s.sawAddress = "READ_BASE:" + err.Error()
		return
	}
	expectedH := md5.Sum([]byte(testSeed + xstream.Salt))
	if string(base[128:144]) != string(expectedH[:]) {
		s.sawAddress = "BAD_H"
		return
	}
	if string(base[144:144+len(extraKey)]) != string(extraKey) {
		s.sawAddress = "BAD_KEY"
		return
	}
	marker := make([]byte, 1)
	if _, err = io.ReadFull(conn, marker); err != nil {
		s.sawAddress = "READ_MARKER:" + err.Error()
		return
	}
	if marker[0] != 0x10 {
		s.sawAddress = "BAD_MARKER"
		return
	}
	clientIV := make([]byte, 16)
	if _, err = io.ReadFull(conn, clientIV); err != nil {
		s.sawAddress = "READ_IV:" + err.Error()
		return
	}

	aesKey := md5.Sum([]byte(testSeed))
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		s.sawAddress = "AES:" + err.Error()
		return
	}
	decryptor := cipher.NewCTR(block, clientIV)

	buffer := make([]byte, 4096)
	count, err := conn.Read(buffer)
	if err != nil && count == 0 {
		s.sawAddress = "READ_DATA:" + err.Error()
		return
	}
	plain := make([]byte, count)
	decryptor.XORKeyStream(plain, buffer[:count])
	s.sawAddress = string(plain)

	// Reply in the same shape with a fresh IV.
	serverIV := make([]byte, 16)
	for i := range serverIV {
		serverIV[i] = byte(i * 7)
	}
	if _, err = conn.Write(make([]byte, baseLength)); err != nil {
		return
	}
	if _, err = conn.Write([]byte{0x10}); err != nil {
		return
	}
	if _, err = conn.Write(serverIV); err != nil {
		return
	}
	body := []byte("HTTP/1.1 204 No Content\r\n\r\n")
	encryptor := cipher.NewCTR(block, serverIV)
	encrypted := make([]byte, len(body))
	encryptor.XORKeyStream(encrypted, body)
	_, _ = conn.Write(encrypted)
}

// TestOutboundEndToEnd drives a real TCP round trip against the fake server.
func TestOutboundEndToEnd(t *testing.T) {
	server := startFakeServer(t)
	defer server.listener.Close()

	host, portText, err := net.SplitHostPort(server.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}

	options := option.HeysocksXhttpOutboundOptions{
		Password:  testSeed + ":" + testExtraHex,
		FakeNet:   &option.FakeNetOptions{TCP: testFakeHex},
		Host:      "apple.com",
		Path:      "/hEK8lz27",
		DebugWire: true,
	}
	options.Server = host
	options.ServerPort = uint16(port)

	instance, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", options)
	if err != nil {
		t.Fatal(err)
	}
	handler := instance.(*Outbound)
	conn, err := handler.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("www.gstatic.com:80"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4096)
	count := 0
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for count < len(response) {
		n, readErr := conn.Read(response[count:])
		count += n
		if readErr != nil || count > 0 {
			break
		}
	}
	if count == 0 {
		t.Fatal("no response from fake server")
	}
	if string(response[:count]) != "HTTP/1.1 204 No Content\r\n\r\n" {
		t.Fatalf("response = %q", response[:count])
	}
	<-server.done
	// The server reads the encrypted address and the following payload in one
	// go, so assert on the address prefix rather than exact equality.
	if !strings.HasPrefix(server.sawAddress, "\x03\x0fwww.gstatic.com\x00\x50") {
		t.Fatalf("server saw %q", server.sawAddress)
	}
}
