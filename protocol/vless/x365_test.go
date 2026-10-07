package vless

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
)

func TestX365WireTCP(t *testing.T) {
	key, err := x365UUID("12345678-1234-1234-1234-123456789abc")
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn := newX365Conn(left, key, vmess.CommandTCP, M.ParseSocksaddr("example.com:443"))
	done := make(chan error, 1)
	go func() {
		header := make([]byte, 4+1+1+16+2+1+1+len("example.com")+3)
		if _, err := io.ReadFull(right, header); err != nil {
			done <- err
			return
		}
		expected := append([]byte("X365\x01\x01"), key[:]...)
		expected = append(expected, 0x01, 0xbb, 0x02, byte(len("example.com")))
		expected = append(expected, []byte("example.com")...)
		expected = append(expected, []byte("hey")...)
		if !bytes.Equal(header, expected) {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, err := right.Write([]byte("X365\x00ok"))
		done <- err
	}()
	if _, err := conn.Write([]byte("hey")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "ok" {
		t.Fatalf("response %q", response)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestX365StatusByteRejectsNonZero(t *testing.T) {
	key, err := x365UUID("12345678-1234-1234-1234-123456789abc")
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn := newX365Conn(left, key, vmess.CommandTCP, M.ParseSocksaddr("example.com:443"))
	go func() { _, _ = right.Write([]byte("X365\x7fok")) }()
	_, err = conn.Read(make([]byte, 2))
	if err == nil || !strings.Contains(err.Error(), "status=127") {
		t.Fatalf("non-zero status must be rejected, got %v", err)
	}
}

func TestX365StatusByteAcceptsZero(t *testing.T) {
	key, err := x365UUID("12345678-1234-1234-1234-123456789abc")
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn := newX365Conn(left, key, vmess.CommandTCP, M.ParseSocksaddr("example.com:443"))
	go func() { _, _ = right.Write([]byte("X365\x00ok")) }()
	out := make([]byte, 2)
	if _, err = io.ReadFull(conn, out); err != nil || string(out) != "ok" {
		t.Fatalf("status 0 must pass: response %q, error %v", out, err)
	}
}

// 字节级向量：帧布局必须与参考实现一致
//   off 0  'X365' | 4  0x01 | 5  command | 6  key(16) | 22 port(2, BE) | 24 atyp | 25 addr
func TestX365FrameByteLayout(t *testing.T) {
	key, err := x365UUID("12345678-1234-1234-1234-123456789abc")
	if err != nil {
		t.Fatal(err)
	}
	domain, err := x365Header(key, vmess.CommandTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	expectedDomain := []byte("X365\x01\x01")
	expectedDomain = append(expectedDomain, key[:]...)
	expectedDomain = append(expectedDomain, 0x01, 0xbb)       // port 443 大端，在 atyp 之前
	expectedDomain = append(expectedDomain, 0x02, byte(len("example.com")))
	expectedDomain = append(expectedDomain, []byte("example.com")...)
	if !bytes.Equal(domain, expectedDomain) {
		t.Fatalf("domain frame mismatch\n got %x\nwant %x", domain, expectedDomain)
	}
	if len(domain) != 26+len("example.com") {
		t.Fatalf("domain frame length %d, want %d", len(domain), 26+len("example.com"))
	}

	ipv4, err := x365Header(key, vmess.CommandTCP, M.ParseSocksaddr("1.2.3.4:443"))
	if err != nil {
		t.Fatal(err)
	}
	expectedIPv4 := []byte("X365\x01\x01")
	expectedIPv4 = append(expectedIPv4, key[:]...)
	expectedIPv4 = append(expectedIPv4, 0x01, 0xbb, 0x01, 1, 2, 3, 4)
	if !bytes.Equal(ipv4, expectedIPv4) {
		t.Fatalf("ipv4 frame mismatch\n got %x\nwant %x", ipv4, expectedIPv4)
	}
	if len(ipv4) != 29 {
		t.Fatalf("ipv4 frame length %d, want 29", len(ipv4))
	}

	ipv6, err := x365Header(key, vmess.CommandUDP, M.ParseSocksaddr("[2001:db8::1]:53"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ipv6) != 41 {
		t.Fatalf("ipv6 frame length %d, want 41", len(ipv6))
	}
	if ipv6[5] != vmess.CommandUDP || ipv6[22] != 0x00 || ipv6[23] != 0x35 || ipv6[24] != 0x03 {
		t.Fatalf("ipv6 frame header mismatch: %x", ipv6[:25])
	}
}

func TestX365InvalidResponsePrefix(t *testing.T) {
	key, err := x365UUID("12345678-1234-1234-1234-123456789abc")
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn := newX365Conn(left, key, vmess.CommandTCP, M.ParseSocksaddr("example.com:443"))
	go func() { _, _ = right.Write([]byte("<html")) }()
	_, err = conn.Read(make([]byte, 1))
	if err == nil || !strings.Contains(err.Error(), "prefix_hex=3c68746d6c") {
		t.Fatalf("unexpected response diagnostic: %v", err)
	}
}

func TestX365WireUDP(t *testing.T) {
	key, err := x365UUID("12345678-1234-1234-1234-123456789abc")
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	dst := M.ParseSocksaddr("127.0.0.1:53")
	conn := &x365PacketConn{newX365Conn(left, key, vmess.CommandUDP, dst), dst}
	done := make(chan error, 1)
	go func() {
		header := make([]byte, 4+1+1+16+2+1+4+2+4)
		if _, err := io.ReadFull(right, header); err != nil {
			done <- err
			return
		}
		if string(header[:4]) != "X365" || header[5] != vmess.CommandUDP || binary.BigEndian.Uint16(header[len(header)-6:len(header)-4]) != 4 || string(header[len(header)-4:]) != "ping" {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, err := right.Write([]byte("X365\x00\x00\x04pong"))
		done <- err
	}()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = left.SetReadDeadline(time.Now().Add(time.Second))
	reply := make([]byte, 16)
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatal(err)
	}
	if string(reply[:n]) != "pong" {
		t.Fatalf("reply %q", reply[:n])
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
