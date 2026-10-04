package aha

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func testPacket() []byte {
	p := make([]byte, 24)
	p[0] = 0x46
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 6
	var sum uint32
	for i := 0; i < len(p); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	return p
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return w.Buffer.Write(p)
}
func TestFramer(t *testing.T) {
	p := testPacket()
	f := Framer{Reader: bytes.NewReader(append(append([]byte{}, p...), p...))}
	for i := 0; i < 2; i++ {
		got, err := f.ReadPacket()
		if err != nil || !bytes.Equal(got, p) {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
	if _, err := f.ReadPacket(); err != io.EOF {
		t.Fatalf("EOF: %v", err)
	}
	f.Reader = bytes.NewReader(p[:21])
	if _, err := f.ReadPacket(); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated: %v", err)
	}
	p[10] ^= 1
	if ValidatePacket(p) == nil {
		t.Fatal("checksum accepted")
	}
	f.Reader = strings.NewReader("HTTP/1.1 404 Not Found\r\n")
	if _, err := f.ReadPacket(); err == nil {
		t.Fatal("HTTP fallback accepted")
	}
}
func TestWriteAll(t *testing.T) {
	w := new(shortWriter)
	p := testPacket()
	f := Framer{Writer: w}
	if err := f.WritePacket(p); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.Bytes(), p) {
		t.Fatal("short write lost bytes")
	}
}
func TestControlEncoding(t *testing.T) {
	p := []Parameter{{"name", "中 :$[], +"}, {"timestamp", "0123456789"}}
	want := "name=%E4%B8%AD+:$[],+%2B&timestamp=0123456789"
	if got := EncodeParameters(p); got != want {
		t.Fatalf("%s", got)
	}
	if BackendHost("tokyo.baidu.com") != "tokyo.wishadmin.com" {
		t.Fatal("backend")
	}
	if SignControl("/light/dispatch/v2", p) == SignControl("/light/dispatch/v2", []Parameter{p[1], p[0]}) {
		t.Fatal("order lost")
	}
}
func TestRejectMissingOrInjectedCredentials(t *testing.T) {
	o := HandshakeOptions{Host: "x.baidu.com", UID: "u", AccessToken: "test-token", Device: "d", Platform: "p", Version: "v", TunnelIP: "10.0.0.2", TunnelGateway: "10.0.0.1"}
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	o.AccessToken = "bad\r\nX: y"
	if o.Validate() == nil {
		t.Fatal("header injection accepted")
	}
}
