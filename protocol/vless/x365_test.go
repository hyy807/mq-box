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
		_, err := right.Write([]byte("X365\x01ok"))
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

func TestX365ResponseExtensionByte(t *testing.T) {
	key, err := x365UUID("12345678-1234-1234-1234-123456789abc")
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn := newX365Conn(left, key, vmess.CommandTCP, M.ParseSocksaddr("example.com:443"))
	go func() { _, _ = right.Write([]byte("X365\x7fok")) }()
	out := make([]byte, 2)
	if _, err = io.ReadFull(conn, out); err != nil || string(out) != "ok" {
		t.Fatalf("extension byte compatibility: response %q, error %v", out, err)
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
		_, err := right.Write([]byte("X365\x01\x00\x04pong"))
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
